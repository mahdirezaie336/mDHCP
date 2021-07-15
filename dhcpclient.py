import time
from socket import AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, socket, timeout
import random


class DHCPClient:

    server_port = 6700
    client_port = 6800
    MAX_BYTES = 1024

    def __init__(self, mac_address: str):
        self.__mac_address = mac_address + ':00:00'
        self.__initial_interval = 10
        self.__backoff_cutoff = 120
        self.__ack_timeout = 20
        self.__lease_time = 40

    def start(self):
        print("DHCP client is starting...\n")

        # Opening Sender and Receiver Socket
        with socket(AF_INET, SOCK_DGRAM) as sock:
            destination = ('<broadcast>', DHCPClient.server_port)
            sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
            sock.bind(('0.0.0.0', DHCPClient.client_port))

            # A loop to repeat sending and receiving scenario
            while True:
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
                    self.__initial_interval = max(new_time, self.__backoff_cutoff)
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
                        time.sleep(self.__lease_time/2)
                except timeout:
                    print('DHCP acknowledgement receive timeout. Resending discovery ...')
                    continue

    def make_new_request(self):
        OP = bytes([0x01])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes([random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)])
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1 = bytes([0x00, 0x0C, 0x29, 0xDD])
        CHADDR2 = bytes([0x5C, 0xA7, 0x00, 0x00])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, 3])
        DHCPOptions2 = bytes([50, 4, 0xC0, 0xA8, 0x01, 0x64])
        DHCPOptions3 = bytes([54, 4, 0xC0, 0xA8, 0x01, 0x01])

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1 \
                  + CHADDR2 + CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3

        return package

    def make_new_discovery_message(self):
        OP = bytes([0x01])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = self.make_new_xid()
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x00, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR1_2 = b''.join([i.encode() for i in self.__mac_address.split(':')])
        CHADDR3 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR4 = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR5 = bytes(192)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, 1])
        DHCPOptions2 = bytes([50, 4, 0xC0, 0xA8, 0x01, 0x64])

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR1_2 + \
                    CHADDR3 + CHADDR4 + CHADDR5 + Magiccookie + DHCPOptions1 + DHCPOptions2

        return package

    def make_new_xid(self) -> bytes:
        return b''.join([bytes([random.randint(0, 255)]) for i in range(4)])


if __name__ == '__main__':
    client = DHCPClient('14:cc:20:f3:8b:ea')
    client.start()
