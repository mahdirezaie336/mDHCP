import socket
import json
import struct
from datetime import datetime
from threading import Thread, Lock
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR, SO_BROADCAST
import socket as s
import binascii
from queue import Queue


class DHCPServer(object):

    server_port = 6700
    client_port = 6800
    MAX_BYTES = 1024
    __queues: dict[bytes, Queue]

    def __init__(self, ip_address: str, subnet_mask: str, dns_servers=None):
        # Loading configs from JSON file
        with open('configs.json', 'r') as config_file:
            configs = json.load(config_file)

            # Setting IP Pool
            self.__ip_pool = set()
            if configs['pool_mode'] == 'range':
                ip_range = DHCPServer.ips(configs['range']['from'], configs['range']['to'])
                for i in ip_range:
                    self.__ip_pool.add(DHCPServer.convert_ip_to_bytes(i))
            elif configs['pool_mode'] == 'subnet':
                pass

            self.__lease_time = configs['lease_time']
            self.__reservation_list = configs['reservation_list']
            self.__black_list = configs['black_list']

        self.__queues = {}
        self.__address = DHCPServer.convert_ip_to_bytes(ip_address)
        self.__subnet = DHCPServer.convert_ip_to_bytes(subnet_mask)
        self.__dns_servers = []

        if dns_servers is None:
            dns_servers = ['8.8.8.8', '1.1.1.1']
        for i in dns_servers:
            self.__dns_servers.append(DHCPServer.convert_ip_to_bytes(i))

    def start(self):
        print("DHCP server is starting...\n")
        server_socket = socket(AF_INET, SOCK_DGRAM)
        server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        server_socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        server_socket.bind(('', DHCPServer.server_port))

        while True:
            try:
                print("Wait DHCP discovery.")
                message, address = server_socket.recvfrom(DHCPServer.MAX_BYTES)
                print("Receive DHCP discovery.")
                parsed_message = self.parse_message(message)
                xid = parsed_message['XID']
                if xid not in self.__queues:
                    if parsed_message['option1'][2:4] == b'01':
                        self.__queues[xid] = Queue()
                        self.__queues[xid].add(parsed_message)
                        Thread(target=self.client_thread, args=(xid,)).start()
                else:
                    self.__queues[xid].add(self.parse_message(message))
            except:
                pass

    def client_thread(self, xid: bytes):
        # Open Sender Socket
        with socket(AF_INET, SOCK_DGRAM) as sender_socket:
            destination = ('255.255.255.255', DHCPServer.client_port)
            sender_socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

            # Getting from queue
            try:
                parsed_message = self.__queues[xid].pop()
            except TimeoutError as e:
                print(xid, ':', e)
                return

            # Checking if mac address is in black list
            mac_address = parsed_message['CHADDR12'][:12]
            if not self.mac_address_is_allowed(mac_address):
                print(xid, ':', mac_address.decode(), 'is in black list.\n')
                return

            # Sending Offer
            print(xid, ':', "Send DHCP offer.")
            offer_message = self.make_offer_message(xid)
            sender_socket.sendto(offer_message, destination)

            while True:
                # Getting request from queue
                print("Wait DHCP request.")
                try:
                    parsed_message = self.__queues[xid].pop(self.__lease_time)
                except TimeoutError as e:
                    print(xid, ':', e)
                    break
                print(xid, ':', "Receive DHCP request.")
                print(xid, ':', "Send DHCP Ack.\n")
                ack_message = self.make_ack_message(parsed_message, ip_address)
                sender_socket.sendto(ack_message, destination)

    def mac_address_is_allowed(self, mac_address: bytes):
        return mac_address not in self.__black_list

    def make_offer_message(self, xid: bytes):
        # Getting an ip address from ip pool
        ip_address = self.__ip_pool.pop()

        # Generating message
        message = self.create_messge()
        message[4] = xid
        message[8] = ip_address
        message[9] = self.__address

        # Adding options
        message.append(b'\x35\x02\x02')                                                 # DHCP Message Type
        message.append(b'\x01\x04' + self.__subnet)                                     # Subnet Mask
        message.append(b'\x03\x04' + self.__address)                                    # Router Address
        message.append(b'\x33\x04' + bytes([self.__lease_time]))                        # Lease Time
        message.append(b'\x36\x04' + self.__address)                                    # DHCP Address

        n = len(self.__dns_servers)
        message.append(b'\x06' + bytes([n * 4]) + b''.join(self.__dns_servers))         # DNS Servers

        return b''.join(message)

    def make_ack_message(self, parsed_request, yiaddr):

        return 'packet'

    def create_messge(self) -> list[bytes]:
        """ Creates body of DHCP message without options. Options
            are created in offer or acknowledgement methods. """
        message = [b'\x02',                     # OP
                   b'\x01',                     # HTYPE
                   b'\x06',                     # HLEN
                   b'\x00',                     # HOPS
                   b'\x00\x00\x00\x00',         # XID
                   b'\x00\x00',                 # SECS
                   b'\x00\x00',                 # FLAGS
                   b'\x00\x00\x00\x00',         # CIADDR
                   b'\x00\x00\x00\x00',         # YIADDR
                   b'\x00\x00\x00\x00',         # SIADDR
                   b'\x00\x00\x00\x00',         # GIADDR
                   # CHADDR1 CHADDR2
                   b''.join([binascii.unhexlify(i) for i in (self.__mac_address + ':00:00').split(':')]),
                   b'\x00\x00\x00\x00',         # CHADDR3
                   b'\x00\x00\x00\x00',         # CHADDR4
                   b'\x00' * 192,               # SNAME and BNAME
                   b'\x63\x82\x53\x63',         # Magic Cookie
                   ]
        return message

    def parse_message(self, response):
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
                         'CHADDR12': message[56:72],
                         'CHADDR3': message[72:80],
                         'CHADDR4': message[80:88],
                         'SName': message[88:216],
                         'BName': message[216:472],
                         'MCookie': message[472:480],
                         'option1': message[480:488]}

        return parsed_packet

    @staticmethod
    def ips(start, end):
        start = struct.unpack('>I', s.inet_aton(start))[0]
        end = struct.unpack('>I', s.inet_aton(end))[0]
        return [s.inet_ntoa(struct.pack('>I', i)) for i in range(start, end)]

    @staticmethod
    def convert_ip_to_bytes(ip_address: str) -> bytes:
        parts = ip_address.split('.')
        return b''.join([bytes([int(i)]) for i in parts])


if __name__ == '__main__':
    dhcp_server = DHCPServer('192.168.1.1')
    dhcp_server.start()
