from socket import socket, htons, AF_PACKET, SOCK_RAW
from struct import unpack

from .utils import *

class Sniffer():
    # Listen for network traffic and write it on stdout
    def init(self):
        return None

    def unpack_ethernet_frame(self, raw_data):
        dest_mac, src_mac, proto = unpack('! 6s 6s H', raw_data[:14])
        return format_mac_addr(dest_mac), format_mac_addr(src_mac), htons(proto), raw_data[14:]

    def unpack_icmp_packet(self, data):
        icmp_type, code, checksum = unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]

    def unpack_tcp_segment(self, data):
        (src_port, dest_port, seq, ack, offset_reserved_flags) = unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        return src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

    def unpack_udp_segment(self, data):
        src_port, dest_port, size = unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]
    
    def unpack_ipv4_packet(self, data):
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, format_ipv4(src), format_ipv4(target), data[header_length:]

    def run(self):
        self.conn = socket(AF_PACKET, SOCK_RAW, htons(3))

        while True:
            raw_data, addr = self.conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = self.unpack_ethernet_frame(raw_data)
            print("\nEthernet Frame")
            print(TAB_1 + "Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))

            # IPv4
            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = self.unpack_ipv4_packet(data)
                print(TAB_1 + "IPv4 Packet:")
                print(TAB_2 + "Version: {}, Header Length: {}, TTL: {}".format(version, header_length, ttl))
                print(TAB_2 + "Protocol: {}, Source: {}, Target: {}".format(proto, src, target))

                # ICMP
                if proto == 1:
                    icmp_type, code, checksum, data = self.unpack_icmp_packet(data)
                
                # TCP
                elif proto == 6:
                    src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = self.unpack_tcp_segment(data)
                    print(TAB_1 + "TCP Segment:")
                    print(TAB_2 + "Source Port: {}, Destination Port: {}".format(src_port, dest_port))
                    print(TAB_2 + "Sequence: {}, Acknowledgment: {}".format(seq, ack))
                    print(TAB_2 + "Flags:")
                    print(TAB_3 + "URG {}, ACK {}, PSH {}, REST {}, SYN {}, FIN {}".format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                    print(TAB_2 + "Data:")
                    print(TAB_3 + format_multi_line(DATA_TAB_3, data))

                # UDP
                elif proto == 17:
                    src_port, dest_port, length, data = self.unpack_udp_segment(data)
                    print(TAB_1 + "UDP Segment:")
                    print(TAB_2 + "Source Port: {}, Destination Port: {}, Length: {}".format(src_port, dest_port , length))
                
                else:
                    print(TAB_1 + "Data:")
                    print(format_multi_line(DATA_TAB_2, data))
            else:
                print("Data:")
                print(format_multi_line(DATA_TAB_1, data))

