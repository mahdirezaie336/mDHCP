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
    queues: dict[bytes, Queue]

    def __init__(self, ip_address: str):
        # Loading configs from JSON file
        with open('configs.json', 'r') as config_file:
            configs = json.load(config_file)

            # Setting IP Pool
            self.__ip_pool = set()
            if configs['pool_mode'] == 'range':
                ip_range = DHCPServer.ips(configs['range']['from'], configs['range']['to'])
                for i in ip_range:
                    self.__ip_pool.add(i)
            elif configs['pool_mode'] == 'subnet':
                pass

            self.__lease_time = configs['lease_time']
            self.__reservation_list = configs['reservation_list']
            self.__black_list = configs['black_list']

        self.queues = {}
        self.address = ip_address
        self.client_num = 0

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
                if xid not in self.queues:
                    if parsed_message['option1'][2:4] == b'01':
                        self.queues[xid] = Queue()
                        self.queues[xid].add(parsed_message)
                        Thread(target=self.client_thread, args=(xid,)).start()
                else:
                    self.queues[xid].add(self.parse_message(message))
            except:
                pass

    def client_thread(self, xid: bytes):
        # Open Sender Socket
        with socket(AF_INET, SOCK_DGRAM) as sender_socket:
            destination = ('255.255.255.255', DHCPServer.client_port)
            sender_socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

            # Getting from queue
            try:
                parsed_message = self.queues[xid].pop()
            except TimeoutError as e:
                print(e)
                return

            # Checking if mac address is in black list
            mac_address = parsed_message['CHADDR12'][:12]
            if not self.mac_address_is_allowed(mac_address):
                print(xid, ':', mac_address.decode(), 'is in black list.\n')
                return

            # Sending Offer
            print(xid, ':', "Send DHCP offer.")
            offer_message = self.make_offer_message(parsed_message, ip_address)
            sender_socket.sendto(offer_message, destination)

            while True:
                # Getting request from queue
                print("Wait DHCP request.")
                try:
                    parsed_message = self.queues[xid].pop(self.__lease_time)
                except TimeoutError as e:
                    print(e)
                    break
                print("Receive DHCP request.")
                print("Send DHCP Ack.\n")
                ack_message = self.get_acknowledgement_message(parsed_message, ip_address)
                sender_socket.sendto(ack_message, destination)
                self.allocate_IP(ip_address, status)

    def mac_address_is_allowed(self, mac_address: bytes):
        return mac_address not in self.__black_list

    def make_offer_message(self, parsed_discovery, your_ip_address):


        return 'packet'

    def get_acknowledgement_message(self, parsed_request, yiaddr):
        ack_dict = self.create_messge()
        # now we should modify some fields
        #  modify xid
        xid = parsed_request['XID']
        ack_dict['XID'] = bytes([int(xid[0:2], 16), int(xid[2:4], 16), int(xid[4:6], 16), int(xid[6:8], 16)])
        #  modify yiaddr field
        yiaddr_parts = yiaddr.split('.')
        ack_dict['YIADDR'] = bytes(
            [int(yiaddr_parts[0]), int(yiaddr_parts[1]), int(yiaddr_parts[2]), int(yiaddr_parts[3])])
        #  modify siaddr
        siaddr_parts = self.address.split('.')
        ack_dict['SIADDR'] = bytes(
            [int(siaddr_parts[0]), int(siaddr_parts[1]), int(siaddr_parts[2]), int(siaddr_parts[3])])
        #  modify mac address
        mac1 = parsed_request['CHADDR1']
        mac2 = parsed_request['CHADDR2']
        ack_dict['CHADDR1'] = bytes([int(mac1[0:2], 16), int(mac1[2:4], 16), int(mac1[4:6], 16), int(mac1[6:8], 16)])
        ack_dict['CHADDR2'] = bytes([int(mac2[0:2], 16), int(mac2[2:4], 16), int(mac2[4:6], 16), int(mac2[6:8], 16)])
        ack_dict['option1'] = bytes([0, 0, 53, 5])
        # at the end we should join the values of dhcp ACK dictionary
        packet = b''.join(ack_dict.values())

        return packet

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


if __name__ == '__main__':
    dhcp_server = DHCPServer('192.168.1.1')
    dhcp_server.start()
