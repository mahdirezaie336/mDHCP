import random
import socket
import json
from threading import Thread
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR, SO_BROADCAST
from queue import Queue, Empty
from utils import *
from datetime import datetime, timedelta


class DHCPServer(object):
    """ This class is the DHCP server which first listens to the specified UDP port.
        When it gets requests from any clients, sends offer and acknowledgement to
        them and handle them on a separated thread. """

    server_port = 6700
    client_port = 6800
    MAX_BYTES = 1024
    __queues: dict[bytes, Queue]

    def __init__(self, ip_address: str, subnet_mask: str, dns_servers=None):
        self.__queues = {}
        self.__address = ip_to_bytes(ip_address)
        self.__subnet = ip_to_bytes(subnet_mask)
        self.__dns_servers = []
        self.__ip_address_table = {}

        # Generating DNS servers
        if dns_servers is None:
            dns_servers = ['8.8.8.8', '1.1.1.1']
        for i in dns_servers:
            self.__dns_servers.append(ip_to_bytes(i))

        # Loading configs from JSON file
        with open('configs.json', 'r') as config_file:
            configs = json.load(config_file)

            # Setting IP Pool
            self.__ip_pool = set()
            if configs['pool_mode'] == 'range':
                ip_range = ips(configs['range']['from'], configs['range']['to'])
                for i in ip_range:
                    self.__ip_pool.add(ip_to_bytes(i))
            elif configs['pool_mode'] == 'subnet':
                ip_range = ip_range_by_subnet(configs['subnet']['ip_block'], configs['subnet']['subnet_mask'])
                for i in ip_range:
                    self.__ip_pool.add(ip_to_bytes(i))

            reservation_list = {}
            for key in configs['reservation_list']:
                reservation_list[mac_to_bytes(key)] = ip_to_bytes(configs['reservation_list'][key])

            self.__lease_time = configs['lease_time']
            self.__reservation_list = reservation_list
            self.__black_list = {mac_to_bytes(i) for i in configs['black_list']}

    def start(self):
        """ Starts listening on the specified port and waiting for a broadcast message.
            If got one, passes them on their thread or makes a new thread. Then the thread
            handles the client."""

        print("DHCP server is starting...\n")
        print("Wait DHCP discovery.")
        server_socket = socket(AF_INET, SOCK_DGRAM)
        server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        server_socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        server_socket.bind(('', DHCPServer.server_port))

        # Staring interpreter
        Thread(target=self.interpreter_thread).start()

        # The listener
        while True:
            message, address = server_socket.recvfrom(DHCPServer.MAX_BYTES)
            parsed_message = self.parse_message(message)
            xid = parsed_message['XID']

            # If message is a new request
            if xid not in self.__queues:
                if parsed_message['OPTIONS'][2:3] == b'\x01':
                    self.__queues[xid] = Queue()
                    self.__queues[xid].put(parsed_message)
                    Thread(target=self.client_thread, args=(xid,)).start()
            else:
                self.__queues[xid].put(self.parse_message(message))

    def client_thread(self, xid: bytes):
        """ This is client handling thread. After getting a discovery this thread run
            and sends offer and ack when needed.
            :param xid The XID related to this session
            """

        prefix = bin_to_str(xid) + ':'
        # Open Sender Socket
        with socket(AF_INET, SOCK_DGRAM) as sender_socket:
            destination = ('255.255.255.255', DHCPServer.client_port)
            sender_socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
            # Getting from queue
            try:
                parsed_message = self.__queues[xid].get(timeout=120)
            except Empty as e:
                print(prefix, 'Waiting for discovery timed out.')
                return

            # Checking if mac address is in black list
            mac_address = parsed_message['CHADDR12'][:6]
            if mac_address in self.__black_list:
                print(prefix, mac_to_str(mac_address), 'is in black list.\n')
                return

            # Sending Offer
            print(prefix, "Send DHCP offer.")
            ip, offer_message = self.make_offer_message(parsed_message)
            sender_socket.sendto(offer_message, destination)

            while True:
                # Getting request from queue
                print(prefix, "Wait DHCP request.")
                try:
                    parsed_message = self.__queues[xid].get(timeout=self.__lease_time)
                    # print(parsed_message['SIADDR'] == self.__address)
                    if parsed_message['SIADDR'] != self.__address:
                        print('The client chose another DHCP with address', ip_to_str(parsed_message['SIADDR']))
                        break
                except Empty as e:
                    print(prefix, 'Lease timed out.')
                    break

                # Sending Ack
                print(prefix, "Receive DHCP request.")
                print(prefix, "Send DHCP Ack.\n")
                ack_message = self.make_ack_message(parsed_message, ip)
                sender_socket.sendto(ack_message, destination)

                # Add address and other info to ip table
                computer_name = 'DESKTOP-' + str(random.randint(0, 2571003))
                table_row = ip, computer_name, str(datetime.now() + timedelta(seconds=self.__lease_time))
                self.__ip_address_table[mac_address] = table_row

            # After lease timed out
            self.__ip_pool.add(ip)
            del self.__ip_address_table[mac_address]

    def interpreter_thread(self):
        """ This will be run on a thread to get input from user to show connected clients. """
        while True:
            inp = input()
            if inp.startswith('s'):
                print(self.__ip_address_table)

    def make_offer_message(self, request_message: dict[str: bytes]):
        """ This creates offer message and returns it. """

        xid = request_message['XID']
        chaddr12 = request_message['CHADDR12']

        # Getting an ip address from ip pool
        ip_address = self.get_an_ip(chaddr12[:6])

        # Generating message
        message = self.create_messge()
        message['XID'] = xid
        message['YIADDR'] = ip_address
        message['SIADDR'] = self.__address
        message['CHADDR12'] = chaddr12

        # Adding options
        options = []
        options.append(b'\x35\x01\x02')                                                 # DHCP Message Type
        options.append(b'\x33\x04' + bytes([self.__lease_time]))                        # Lease Time
        options.append(b'\x01\x04' + self.__subnet)                                     # Subnet Mask
        options.append(b'\x03\x04' + self.__address)                                    # Router Address
        options.append(b'\x36\x04' + self.__address)                                    # DHCP Address

        n = len(self.__dns_servers)
        options.append(b'\x06' + bytes([n * 4]) + b''.join(self.__dns_servers))         # DNS Servers
        message['OPTIONS'] = b''.join(options)

        return ip_address, b''.join(message.values())

    def make_ack_message(self, request_message: dict[str: bytes], client_ip: bytes):
        """ This creates ack message and returns it. """

        xid = request_message['XID']
        chaddr12 = request_message['CHADDR12']

        # Generating message
        message = self.create_messge()
        message['XID'] = xid
        message['YIADDR'] = client_ip
        message['SIADDR'] = self.__address
        message['CHADDR12'] = chaddr12

        # Adding options
        options = []
        options.append(b'\x35\x01\x05')                                                 # DHCP Message Type
        options.append(b'\x33\x04' + bytes([self.__lease_time]))                        # Lease Time
        options.append(b'\x01\x04' + self.__subnet)                                     # Subnet Mask
        options.append(b'\x03\x04' + self.__address)                                    # Router Address
        options.append(b'\x36\x04' + self.__address)                                    # DHCP Address

        n = len(self.__dns_servers)
        options.append(b'\x06' + bytes([n * 4]) + b''.join(self.__dns_servers))         # DNS Servers
        message['OPTIONS'] = b''.join(options)

        return b''.join(message.values())

    def get_an_ip(self, mac_address: bytes) -> bytes:
        """ Gets an ip from ip pool considering the conditions """

        # If lease time is not out
        if mac_address in self.__ip_address_table:
            return self.__ip_address_table[mac_address][0]

        # If mac address is in reservation list
        if mac_address in self.__reservation_list:
            ip = self.__reservation_list[mac_address]
            self.__ip_pool.remove(ip)
            return ip

        return self.__ip_pool.pop()

    def create_messge(self) -> dict[str: bytes]:
        """ Creates body of DHCP message without options. Options
            are created in offer or acknowledgement methods. """
        message = {'OP': b'\x02',                           # OP
                   'HTYPE': b'\x01',                        # HTYPE
                   'HLEN': b'\x06',                         # HLEN
                   'HOPS': b'\x00',                         # HOPS
                   'XID': b'\x00\x00\x00\x00',              # XID
                   'SECS': b'\x00\x00',                     # SECS
                   'FLAGS': b'\x00\x00',                    # FLAGS
                   'CIADDR': b'\x00\x00\x00\x00',           # CIADDR
                   'YIADDR': b'\x00\x00\x00\x00',           # YIADDR
                   'SIADDR': b'\x00\x00\x00\x00',           # SIADDR
                   'GIADDR': b'\x00\x00\x00\x00',           # GIADDR
                   'CHADDR12': b'\x00' * 8,
                   'CHADDR3': b'\x00\x00\x00\x00',          # CHADDR3
                   'CHADDR4': b'\x00\x00\x00\x00',          # CHADDR4
                   'SNAME_BNAME': b'\x00' * 192,            # SNAME and BNAME
                   'MagicCookie': b'\x63\x82\x53\x63',      # Magic Cookie
                    }
        return message

    def parse_message(self, message):
        """ Parses the response message. """
        parsed_packet = {'OP': message[0:1],
                         'HTYPE': message[1:2],
                         'HLEN': message[2:3],
                         'HOPS': message[3:4],
                         'XID': message[4:8],
                         'SECS': message[8:10],
                         'FLAGS': message[10:12],
                         'CIADDR': message[12:16],
                         'YIADDR': message[16:20],
                         'SIADDR': message[20:24],
                         'GIADDR': message[24:28],
                         'CHADDR12': message[28:36],
                         'CHADDR3': message[36:40],
                         'CHADDR4': message[40:44],
                         'SNAME': message[44:108],
                         'BNAME': message[108:236],
                         'MCOOKIE': message[236:240],
                         'OPTIONS': message[240:]}

        return parsed_packet


if __name__ == '__main__':
    dhcp_server = DHCPServer('192.168.1.1', '255.255.255.0')
    dhcp_server.start()
