import socket
import struct
import time
import sys
from collections import defaultdict, deque

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1


def mac_to_str(mac_bytes):
	return ':'.join('%02x' % b for b in mac_bytes)


def ip_to_str(ip_bytes):
	return socket.inet_ntoa(ip_bytes)


def set_promiscuous(sock, iface):
	ifindex = socket.if_nametoindex(iface)
	mreq = struct.pack('IHH8s', ifindex, PACKET_MR_PROMISC, 0, b'\x00' * 8)
	sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)


# 1. ARP Spoofing 탐지
# 같은 IP가 다른 MAC으로 바뀌면 스푸핑으로 본다
class ArpSpoofDetector:
	def __init__(self):
		self.ip_to_mac = {}

	def handle_arp(self, packet):
		if len(packet) < 42:
			return
		smac = packet[22:28]
		sip = packet[28:32]

		# 처음 보는 IP는 baseline으로 저장
		known = self.ip_to_mac.get(sip)
		if known is None:
			self.ip_to_mac[sip] = smac
			return
		# MAC이 바뀌었으면 경보
		if known != smac:
			print("[ARP-SPOOF] %s 의 MAC이 %s -> %s 로 변경됨" % (
				ip_to_str(sip), mac_to_str(known), mac_to_str(smac)))
			self.ip_to_mac[sip] = smac


# 2. 특정 패킷 탐지 (HTTP 쿠키 / ICMP / DNS / SSH)
class ConditionDetector:
	def handle_ip(self, packet):
		if len(packet) < 34:
			return
		ip_hdr = packet[14:34]
		ihl = (ip_hdr[0] & 0x0F) * 4
		proto = ip_hdr[9]
		sip = ip_hdr[12:16]
		dip = ip_hdr[16:20]
		l4_start = 14 + ihl

		if proto == IPPROTO_ICMP:
			self._check_icmp(packet, l4_start, sip, dip)
		elif proto == IPPROTO_TCP:
			self._check_tcp(packet, l4_start, sip, dip)
		elif proto == IPPROTO_UDP:
			self._check_udp(packet, l4_start, sip, dip)

	def _check_icmp(self, packet, start, sip, dip):
		if len(packet) < start + 1:
			return
		# type 8 = Echo Request (ping)
		if packet[start] == 8:
			print("[ICMP] %s -> %s Echo Request" % (ip_to_str(sip), ip_to_str(dip)))

	def _check_tcp(self, packet, start, sip, dip):
		if len(packet) < start + 20:
			return
		tcp_hdr = packet[start:start + 20]
		sport, dport = struct.unpack('!HH', tcp_hdr[0:4])
		data_offset = (tcp_hdr[12] >> 4) * 4
		payload = packet[start + data_offset:]

		# HTTP(80)에서 쿠키가 평문으로 보이면 경보
		if dport == 80 or sport == 80:
			if b'Cookie:' in payload or b'Set-Cookie:' in payload:
				print("[HTTP] %s:%d -> %s:%d 평문 쿠키 노출" % (
					ip_to_str(sip), sport, ip_to_str(dip), dport))

		# SSH(22) 배너 관찰
		if dport == 22 or sport == 22:
			if payload.startswith(b'SSH-2.0'):
				print("[SSH] %s:%d <-> %s:%d 배너: %s" % (
					ip_to_str(sip), sport, ip_to_str(dip), dport, payload[:20]))

	def _check_udp(self, packet, start, sip, dip):
		if len(packet) < start + 8:
			return
		sport, dport = struct.unpack('!HH', packet[start:start + 4])
		# DNS(53) 질의 도메인 로깅
		if dport == 53 or sport == 53:
			qname = self._parse_dns_qname(packet[start + 8:])
			if qname:
				print("[DNS] %s -> %s 질의: %s" % (ip_to_str(sip), ip_to_str(dip), qname))

	def _parse_dns_qname(self, dns_payload):
		# DNS 헤더 12바이트 뒤부터 라벨 길이 + 문자 반복
		try:
			pos = 12
			labels = []
			while True:
				length = dns_payload[pos]
				if length == 0:
					break
				labels.append(dns_payload[pos + 1:pos + 1 + length].decode('ascii', 'replace'))
				pos += 1 + length
			return '.'.join(labels)
		except Exception:
			return None


# 3. Port Scan 탐지
# 한 출발지가 짧은 시간에 여러 포트를 SYN으로 두드리면 스캔으로 본다
class PortScanDetector:
	WINDOW = 5.0
	THRESHOLD = 20

	def __init__(self):
		self.history = defaultdict(deque)
		self.alerted = set()

	def handle_tcp_flags(self, sip, dip, dport, syn, ack):
		# SYN만 있고 ACK 없는 연결 시도만 카운트
		if not (syn and not ack):
			return

		now = time.time()
		dq = self.history[sip]
		dq.append((now, dip, dport))

		# WINDOW 밖의 오래된 기록은 버림
		while dq and now - dq[0][0] > self.WINDOW:
			dq.popleft()

		distinct = set((d[1], d[2]) for d in dq)
		if len(distinct) >= self.THRESHOLD:
			# 같은 구간에서 중복 경보 방지
			key = (sip, int(now // self.WINDOW))
			if key not in self.alerted:
				self.alerted.add(key)
				print("[PORT-SCAN] %s 가 %.0f초 동안 서로 다른 %d개 포트 접근 (SYN only)" % (
					ip_to_str(sip), self.WINDOW, len(distinct)))


def usage():
	print("syntax: mini_ids.py <interface>")
	print("sample: mini_ids.py wlan0")


def main():
	if len(sys.argv) != 2:
		usage()
		sys.exit(1)

	iface = sys.argv[1]

	sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
	sock.bind((iface, 0))
	set_promiscuous(sock, iface)

	arp_detector = ArpSpoofDetector()
	cond_detector = ConditionDetector()
	scan_detector = PortScanDetector()

	print("Mini IDS 시작 - interface:", iface)

	while True:
		packet = sock.recv(65536)
		if len(packet) < 14:
			continue
		eth_type = struct.unpack('!H', packet[12:14])[0]

		if eth_type == ETH_P_ARP:
			arp_detector.handle_arp(packet)
			continue

		if eth_type != ETH_P_IP:
			continue

		cond_detector.handle_ip(packet)

		# Port Scan 판단에 필요한 TCP 플래그 추출
		ip_hdr = packet[14:34]
		ihl = (ip_hdr[0] & 0x0F) * 4
		proto = ip_hdr[9]
		if proto != IPPROTO_TCP:
			continue

		sip = ip_hdr[12:16]
		dip = ip_hdr[16:20]
		l4_start = 14 + ihl
		if len(packet) < l4_start + 14:
			continue

		tcp_hdr = packet[l4_start:l4_start + 20]
		dport = struct.unpack('!H', tcp_hdr[2:4])[0]
		flags = tcp_hdr[13]
		syn = bool(flags & 0x02)
		ack = bool(flags & 0x10)
		scan_detector.handle_tcp_flags(sip, dip, dport, syn, ack)


if __name__ == '__main__':
	main()
