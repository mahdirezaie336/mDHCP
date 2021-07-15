import binascii
import time
from socket import AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, socket, timeout
import random


class DHCPClient:
    server_port = 6700
    client_port = 6800
    MAX_BYTES = 1024

    def __init__(self, mac_address: str):
        self.__mac_address = mac_address
        self.__initial_interval = 10
        self.__backoff_cutoff = 120
        self.__ack_timeout = 20
        self.__lease_time = 40
        self.__xid = b''

    def start(self):
        print("DHCP client is starting...\n")

        # Opening Sender and Receiver Socket
        with socket(AF_INET, SOCK_DGRAM) as sock:
            destination = ('<broadcast>', DHCPClient.server_port)
            sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
            sock.bind(('0.0.0.0', DHCPClient.client_port))

            # A loop to repeat sending and receiving scenario
            while True:
                self.refresh_xid()
                try:
                    # Sending discovery
                    data = self.make_discovery_message()
                    print("Sent DHCP discovery.")
                    sock.sendto(data, destination)

                    # Setting the socket timeout
                    sock.settimeout(self.__initial_interval)

                    # Receiving the offer
                    data, address = sock.recvfrom(DHCPClient.MAX_BYTES)
                    print("Receive DHCP offer.")
                except timeout:
                    # Formula of initial interval
                    new_time = self.__initial_interval * 2 * random.random() + self.__initial_interval
                    self.__initial_interval = min(new_time, self.__backoff_cutoff)
                    print('DHCP offer receiving timeout. Resending with initial interval',
                          self.__initial_interval, ' seconds ...')
                    continue

                # DHCP acknowledgement repeater
                try:
                    while True:
                        # Sending request
                        print("Send DHCP request.")
                        data = self.make_request_message(data[32:40], data[40:48])
                        sock.sendto(data, destination)

                        # Setting acknowledgement timeout
                        sock.settimeout(self.__ack_timeout)

                        # Receiving acknowledgement
                        data, address = sock.recvfrom(DHCPClient.MAX_BYTES)
                        print("Receive DHCP pack.\n")
                        print(data)
                        time.sleep(self.__lease_time / 2)
                except timeout:
                    print('DHCP acknowledgement receive timeout. Resending discovery ...')
                    continue

    def make_discovery_message(self):
        message = self.create_messge()
        # Adding options
        message.append(b'\x35\x02\x01')
        return b''.join(message)

    def make_request_message(self, your_ip_address: bytes, server_ip_address: bytes):
        print()
        message = self.create_messge()

        # Changing YIADDR and SIADDR
        message[8] = your_ip_address
        message[9] = server_ip_address

        # Appending Options
        message.append(b'\x35\x02\x03')
        message.append(b'\x34\x04' + your_ip_address)
        message.append(b'\x36\x04' + server_ip_address)
        return b''.join(message)

    def refresh_xid(self):
        self.__xid = b''.join([bytes([random.randint(0, 255)]) for i in range(4)])

    def create_messge(self) -> list[bytes]:
        """ Creates body of DHCP message without options. Options
            are created in request or discovery methods. """
        message = [b'\x01',                             # OP
                   b'\x01',                             # HTYPE
                   b'\x06',                             # HLEN
                   b'\x00',                             # HOPS
                   self.__xid,                          # XID
                   b'\x00\x00',                         # SECS
                   b'\x00\x00',                         # FLAGS
                   b'\x00\x00\x00\x00',                 # CIADDR
                   b'\x00\x00\x00\x00',                 # YIADDR
                   b'\x00\x00\x00\x00',                 # SIADDR
                   b'\x00\x00\x00\x00',                 # GIADDR
                   # CHADDR1 CHADDR2
                   b''.join([bytes([int(i, 16)]) for i in (self.__mac_address + ':00:00').split(':')]),
                   b'\x00\x00\x00\x00',                 # CHADDR3
                   b'\x00\x00\x00\x00',                 # CHADDR4
                   b'\x00' * 192,                       # SNAME and BNAME
                   b'\x63\x82\x53\x63',                 # Magic Cookie
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
                         'CHADDR1': message[56:64],
                         'CHADDR2': message[64:72],
                         'CHADDR3': message[72:80],
                         'CHADDR4': message[80:88],
                         'SNAME': message[88:216],
                         'BNAME': message[216:472],
                         'MCOOKIE': message[472:480],
                         'OPTIONS': message[480:]}
        return parsed_packet


if __name__ == '__main__':
    client = DHCPClient('14:cc:20:f3:8b:ea')
    client.start()
