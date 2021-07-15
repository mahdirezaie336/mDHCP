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
                    print("Send DHCP discovery.")
                    data = self.make_new_discovery_message()
                    sock.sendto(data, destination)

                    # Setting the socket timeout
                    sock.settimeout(self.__initial_interval)

                    # Receiving the offer
                    data, address = sock.recvfrom(DHCPClient.MAX_BYTES)
                    print("Receive DHCP offer.")
                except timeout:
                    new_time = self.__initial_interval * 2 * random.random()
                    self.__initial_interval = min(new_time, self.__backoff_cutoff)
                    print('DHCP offer receiving timeout. Resending with initial interval',
                          self.__initial_interval, ' seconds ...')
                    continue

                # DHCP acknowledgement repeater
                try:
                    while True:
                        # Sending request
                        print("Send DHCP request.")
                        data = self.make_new_request()
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

    def make_new_request(self):


        return

    def make_new_discovery_message(self):


        return

    def create_messge(self) -> list[bytes]:
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
                   b''.join([binascii.unhexlify(i) for i in (self.__mac_address + ':00:00').split(':')]),
                   b'\x00\x00\x00\x00',                 # CHADDR3
                   b'\x00\x00\x00\x00',                 # CHADDR4
                   b'\x00' * 192,                       # SNAME and BNAME
                   b'\x63\x82\x53\x63'                  # Magic Cookie
                   b'\x00\x00\x53\x01'                  # OPTION1
                   ]
        return message

    def refresh_xid(self) -> bytes:
        self.__xid = b''.join([bytes([random.randint(0, 255)]) for i in range(4)])


if __name__ == '__main__':
    client = DHCPClient('14:cc:20:f3:8b:ea')
    client.start()
