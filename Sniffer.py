#If anyone knows how to fix the unpacking issue @ line 33 for tcp flags, please let me know
#File "Sniffer.py", line 33, in main
    #src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = tcp_packet(data)
#ValueError: too many values to unpack (expected 10)



import socket
import sys
import struct
import textwrap


#Packet Listen

def main():
	s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

	while True:
		raw_data, addr = s.recvfrom(65536)
		#Store raw data to variables and send to eth frame function

		dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
		print("Destination: {}, Source: {}, Protocol {}:".format(dest_mac, src_mac, eth_proto))


		#IF PROTOCOL FOR IPV4 ETHERNET EXISTS


		if eth_proto == 8:
			(version, headerLength, ttl, proto, src, target, data) = ipv4_packet(data)
			print("IPv4 Packet: ")
			print("Version: {}, Header Length: {}, TTL: {}".format(version,headerLength, ttl))
			print("Protocol: {}, Source: {}, Target: {}".format(proto, src, target))

			if proto==1:
				icmp_type, code, checksum, data = imcp_packet(data)

			elif proto == 6:
				src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = tcp_packet(data)

			else:
				print("data pass")





#Ethernet Frame


def ethernet_frame(data):
	
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


#Formated MACS
def get_mac_addr(bytes_addr):
	bytes_str = map('{:02x}'.format, bytes_addr)
	return ':'.join(bytes_str).upper()


#IPV4 packet unpacker
def ipv4_packet(data):
	versionHeaderLength = data[0]
	version = versionHeaderLength >> 4

	headerLength = (versionHeaderLength & 15) * 4

	ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return version, headerLength, ttl, proto, ipv4(src), ipv4(target), data[headerLength:]


#Return IPV4 address

def ipv4(addr):
	return '.'.join(map(str,addr))



#ICMP packet

def imcp_packet(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
	return icmp_type, code, checksum, data[4:]


#TCP

def tcp_packet(data):
	(src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
	offset = (offset_reserved_flags >> 12) * 4
	flag_urg = (offset_reserved_flags & 32) >> 5
	flag_ack = (offset_reserved_flags & 16) >> 4
	flag_psh = (offset_reserved_flags & 8) >> 3
	flag_rst = (offset_reserved_flags & 4) >> 2
	flag_syn = (offset_reserved_flags & 2) >> 1
	flag_fin = offset_reserved_flags & 1

	return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

main()
