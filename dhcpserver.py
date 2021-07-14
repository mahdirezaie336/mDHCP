import socket
import json
import struct
from threading import Thread
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR, SO_BROADCAST
import binascii


class DHCPServer(object):

    server_port = 67
    client_port = 68
    MAX_BYTES = 1024

    def __init__(self):
        # Loading configs from JSON file
        with open('configs.json', 'r') as config_file:
            configs = json.load(config_file)
            self.__ip_pool = []
            if configs['pool_mode'] == 'range':
                pass

        self.queues = {}
        pass

    def start(self):
        print("DHCP server is starting...\n")

        serverSocket = socket(AF_INET, SOCK_DGRAM)
        serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        serverSocket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        serverSocket.bind(('', DHCPServer.server_port))
        while 1:
            try:
                print("Wait DHCP discovery.")
                discovery_message, address = serverSocket.recvfrom(DHCPServer.MAX_BYTES)
                print("Receive DHCP discovery.")
                discovery_parsed = self.parseMessage(discovery_message)
                xid = discovery_parsed['XID']
                if xid not in self.queues:
                    if discovery_parsed['option1'][2:4] == bytes([1]):
                        self.queues[xid] = []
                        Thread(target=self.client_thread, args=(serverSocket, discovery_message)).start()
                else:
                    self.queues[xid].append(discovery_message)

            except:
                pass

    def client_thread(self, serverSocket, discovery_message):
        destination = ('255.255.255.255', DHCPServer.client_port)
        print("Send DHCP offer.")
        parsed_discovery = self.parseMessage(discovery_message)
        status, ip_address = self.check_mac(parsed_discovery)
        if status == "blocked":
            return

        offer_message = self.DHCPOffer(parsed_discovery, ip_address)
        serverSocket.sendto(offer_message, destination)
        while 1:
            try:
                print("Wait DHCP request.")
                request_message, address = serverSocket.recvfrom(self.buffer_size)
                print("Receive DHCP request.")
                parsed_request = self.parseMessage(request_message)

                print("Send DHCP Ack.\n")
                ack_message = self.DHCPOffer(parsed_request, ip_address)
                serverSocket.sendto(ack_message, destination)
                self.allocate_IP(ip_address, status)
                self.ip_waiting.remove(ip_address)
            except:
                raise

    def parseMessage(self, response):
        message = binascii.hexlify(response)
        parsed_packet = {'OP': message[0:2],
                         'HTYPE': message[2:4],
                         'HLEN': message[4:6],
                         'HOPS': message[6:8],
                         'XID': message[8:16],
                         'SECS': message[16:20],
                         'FLAGS': message[20:24],
                         'CIADDR': message[24:32],
                         'YIADDR': message[32:40],
                         'SIADDR': message[40:48],
                         'GIADDR': message[48:56],
                         'CHADDR1': message[56:64],
                         'CHADDR2': message[64:72],
                         'CHADDR3': message[72:80],
                         'CHADDR4': message[80:88],
                         'SName': message[88:216],
                         'BName': message[216:472],
                         'MCookie': message[472:480],
                         'option1': message[480:488]}

        return parsed_packet

    @staticmethod
    def offer_get():
        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([0x39, 0x03, 0xF3, 0x26])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0xC0, 0xA8, 0x01, 0x64])  # 192.168.1.100
        SIADDR = bytes([0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x05, 0x3C, 0x04])
        CHADDR2 = bytes([0x8D, 0x59, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, 2])  # DHCP Offer
        DHCPOptions2 = bytes([1, 4, 0xFF, 0xFF, 0xFF, 0x00])  # 255.255.255.0 subnet mask
        DHCPOptions3 = bytes([3, 4, 0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1 router
        DHCPOptions4 = bytes([51, 4, 0x00, 0x01, 0x51, 0x80])  # 86400s(1 day) IP address lease time
        DHCPOptions5 = bytes([54, 4, 0xC0, 0xA8, 0x01, 0x01])  # DHCP server

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5

        return package

    @staticmethod
    def pack_get():
        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([0x39, 0x03, 0xF3, 0x26])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0xC0, 0xA8, 0x01, 0x64])
        SIADDR = bytes([0xC0, 0xA8, 0x01, 0x01])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x05, 0x3C, 0x04])
        CHADDR2 = bytes([0x8D, 0x59, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, 5])  # DHCP ACK(value = 5)
        DHCPOptions2 = bytes([1, 4, 0xFF, 0xFF, 0xFF, 0x00])  # 255.255.255.0 subnet mask
        DHCPOptions3 = bytes([3, 4, 0xC0, 0xA8, 0x01, 0x01])  # 192.168.1.1 router
        DHCPOptions4 = bytes([51, 4, 0x00, 0x01, 0x51, 0x80])  # 86400s(1 day) IP address lease time
        DHCPOptions5 = bytes([54, 4, 0xC0, 0xA8, 0x01, 0x01])  # DHCP server

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4 + DHCPOptions5

        return package

    @staticmethod
    def ips(start, end):
        start = struct.unpack('>I', socket.inet_aton(start))[0]
        end = struct.unpack('>I', socket.inet_aton(end))[0]
        return [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end)]


if __name__ == '__main__':
    dhcp_server = DHCPServer()
    dhcp_server.server()
