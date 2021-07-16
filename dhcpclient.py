import time
from socket import AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, socket, timeout
import random
from utils import *


class DHCPClient:
    """ The dhcp client simulation.
        This class is creates DHCP discovery and DHCP request and broadcasts them into
        networks. First sends discovery message. If got offer, it parses offer and sends
        request. If server accepted request, sends an acknowledgement. By receiving ack
        this client prints the IP that received."""

    server_port = 6700
    client_port = 6800
    MAX_BYTES = 1024

    def __init__(self, mac_address: str):
        self.__mac_address = mac_to_bytes(mac_address)
        self.__initial_interval = 10
        self.__backoff_cutoff = 120
        self.__ack_timeout = 20
        self.__lease_time = 30
        self.__xid = b''

    def start(self):
        """ Starts the client by sending DHCP discovery and waiting for offer. """

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
                    data, address = self.check_and_receive(sock, 2)
                    print("Receive DHCP offer.")
                except timeout:
                    # Formula of initial interval
                    new_time = self.__initial_interval * 2 * random.random() + self.__initial_interval
                    self.__initial_interval = min(new_time, self.__backoff_cutoff)
                    print('DHCP offer receiving timeout. Resending with initial interval',
                          self.__initial_interval, ' seconds ...\n')
                    continue

                parsed_offer = self.parse_message(data)
                # DHCP acknowledgement repeater
                try:
                    while True:
                        # Sending request
                        print("Send DHCP request.")
                        data = self.make_request_message(parsed_offer['YIADDR'], parsed_offer['SIADDR'])
                        sock.sendto(data, destination)

                        # Setting acknowledgement timeout
                        sock.settimeout(self.__ack_timeout)

                        # Receiving acknowledgement
                        data, address = self.check_and_receive(sock, 5)
                        parsed_ack = self.parse_message(data)
                        print("Receive DHCP ack.\n")
                        print('IP Address:', ip_to_str(parsed_ack['YIADDR']), '\n')

                        # Lease time Handling
                        self.__lease_time = parsed_ack['OPTIONS'][5]
                        time.sleep(self.__lease_time / 2)
                except timeout:
                    print('DHCP acknowledgement receive timeout. Resending discovery ...')
                    continue

    def check_and_receive(self, sock: socket, msg_type: int):
        """ Checks whether the message we got has a specific type and has
            XID like what sent previously. Actually checks if the received
            message belongs to us. If no drops the message and waits again. """

        while True:
            data, address = sock.recvfrom(DHCPClient.MAX_BYTES)
            parsed = self.parse_message(data)
            # print(parsed['OPTIONS'][2], msg_type, parsed['OPTIONS'][2] == msg_type)
            if parsed['XID'] == self.__xid and parsed['OPTIONS'][2] == msg_type:
                return data, address

    def make_discovery_message(self):
        """ Creates discovery message to broadcast. """

        message = self.create_message()
        # Adding options
        message.append(b'\x35\x01\x01')
        return b''.join(message)

    def make_request_message(self, your_ip_address: bytes, server_ip_address: bytes):
        """ Creates request message to broadcast. """

        message = self.create_message()

        # Changing YIADDR and SIADDR
        message[8] = your_ip_address
        message[9] = server_ip_address

        # Appending Options
        message.append(b'\x35\x01\x03')
        message.append(b'\x34\x04' + your_ip_address)
        message.append(b'\x36\x04' + server_ip_address)
        return b''.join(message)

    def refresh_xid(self):
        """ Changes XID to a random number. """

        self.__xid = b''.join([bytes([random.randint(0, 255)]) for i in range(4)])

    def create_message(self) -> list[bytes]:
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
                   self.__mac_address + b'\x00\x00',
                   b'\x00\x00\x00\x00',                 # CHADDR3
                   b'\x00\x00\x00\x00',                 # CHADDR4
                   b'\x00' * 192,                       # SNAME and BNAME
                   b'\x63\x82\x53\x63',                 # Magic Cookie
                   ]
        return message

    def parse_message(self, message: bytes) -> dict[str: bytes]:
        """ Parses the message client got, into DHCP fields. """

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
    client = DHCPClient('14:cc:20:f3:8b:ea')
    client.start()
