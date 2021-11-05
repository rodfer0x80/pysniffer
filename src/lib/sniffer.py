import socket
import struct
import textwrap

format_mac_addr = lambda byte_addr: ':'.join(map('{:02x}'.format, byte_addr)).upper()

class Sniffer():
    def init(self):
        return None

    def ethernet_frame(self, raw_data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
        return format_mac_addr(dest_mac), format_mac_addr(src_mac), socket.htons(proto), raw_data[14:]
    
    def run(self):
        self.conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

        while True:
            raw_data, addr = self.conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)
            print("\nEthernet Frame")
            print("Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))