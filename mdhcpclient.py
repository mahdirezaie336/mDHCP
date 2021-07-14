import threading
from socket import *
import binascii
import random

# the DHCP server port
serverPort = 6700
# the DHCP client port
clientPort = 6800


class DHCP_Client:

    def __init__(self, MAC_Addrress):
        # first interval for waiting
        self.initial_interval = 10
        # maximum time of waiting
        self.backoff_cutoff = 120
        self.xid = 0
        # after timeout time if the server doesnt send ack we should send discover message again
        self.timeout = 5
        # the client mac address is assigned to it when it is created
        self.Mac_Address = MAC_Addrress
        # the maximum bytes that can receive or buffer size
        self.buffer_size = 1024
        # the timer related to time of receiving ACK
        self.timer1 = threading.Timer(self.timeout, self.run)

        # the variables related to discover timer
        self.counter = 0
        self.R = self.initial_interval
        self.P = 0.5
        self.timer_formula = 2 * self.R * self.P
        self.timer2 = threading.Timer(self.timer_formula, self.run)

    def run(self):
        print('run ran')
        address, yiaddr, siaddr = self.sendDiscover()
        self.sendRequest(address, yiaddr, siaddr)

    def sendDiscover(self):
        # the configuration of discover timer
        if self.counter > 0:
            self.R = self.timer_formula
            randNum = random.randint(1, 1000)
            self.P = 1 / randNum
            self.timer_formula = 2 * self.R * self.P
            if self.timer_formula >= self.backoff_cutoff:
                raise Exception("backoff_cutoff")
        # first we should broadcast a discover message and get offer message and then close connection
        print("client is starting...\n")
        destination = ('<broadcast>', serverPort)
        client_socket = socket(AF_INET, SOCK_DGRAM)
        client_socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        client_socket.bind(('0.0.0.0', clientPort))

        print("Send DHCP discover message.")
        discover_message = self.DHCPDiscover()
        client_socket.sendto(discover_message, destination)

        # one server get the discover message that is sent recently and send offer message
        # start timer2
        self.counter += 1
        self.timer2.start()
        offer_message, address = client_socket.recvfrom(self.buffer_size)
        self.timer2.cancel()
        print("Receive DHCP offer.")
        # Restore the configuration of timer variables
        self.counter = 0
        self.R = self.initial_interval
        self.P = 0.5
        self.timer_formula = 2 * self.R * self.P
        client_socket.close()

        # we should process the offer message
        parsed_offer = self.parseMessage(offer_message)
        yiaddr = [parsed_offer['YIADDR'][0:2], parsed_offer['YIADDR'][2:4], parsed_offer['YIADDR'][4:6],
                  parsed_offer['YIADDR'][6:8]]
        print(yiaddr)
        siaddr = [parsed_offer['SIADDR'][0:2], parsed_offer['SIADDR'][2:4], parsed_offer['SIADDR'][4:6],
                  parsed_offer['SIADDR'][6:8]]
        return address, yiaddr, siaddr

    def sendRequest(self, address, yiaddr, siaddr, bindAdress ='0.0.0.0'):
        # in the offer message , server put its address
        # now we should send a request message to that server
        destination = address[0], serverPort
        client_socket = socket(AF_INET, SOCK_DGRAM)
        client_socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        client_socket.bind((bindAdress, clientPort))

        print("Send DHCP request.")
        request_message = self.DHCPRequest(yiaddr, siaddr)
        client_socket.sendto(request_message, destination)

        # the timer start. if the ack isn't received we should send discover again
        self.timer1.start()
        ack_message, address = client_socket.recvfrom(self.buffer_size)
        self.timer1.cancel()
        print("Receive DHCP pack.\n")
        parsed_ack = self.parseMessage(ack_message)
        YIADDR = [parsed_ack['YIADDR'][0:2], parsed_ack['YIADDR'][2:4], parsed_ack['YIADDR'][4:6],
                  parsed_ack['YIADDR'][6:8]]
        myIP = '.'.join((str(int(YIADDR[0], 16)), str(int(YIADDR[1], 16)), str(int(YIADDR[2], 16)), str(int(YIADDR[3], 16))))
        print("The IP address is:", myIP)
        client_socket.close()

    def DHCPDiscover(self):
        # first we should generate a specific xid
        self.xid = self.xid_generator()
        # then we should get the general form of message
        dhcp_discover_dict = self.message()
        dhcp_discover_dict['XID'] = bytes(self.xid)
        dhcp_discover_dict['option1'] = bytes([53, 1, 0, 0])
        # at the end we should hexlify the values of dhcp discover dictionary
        packet = b''.join(dhcp_discover_dict.values())
        return packet

    def xid_generator(self):
        xid_4bytes = []
        for i in range(4):
            xid_4bytes.append(random.randint(0, 255))
        return xid_4bytes

    def DHCPRequest(self, yiaddr, siaddr):
        # get the general form of the message
        dhcp_request_dict = self.message()
        # now we should modify some fields
        dhcp_request_dict['YIADDR'] = b''.join(yiaddr)
        dhcp_request_dict['SIADDR'] = b''.join(siaddr)
        dhcp_request_dict['option1'] = bytes([0, 0, 53, 3])
        # at the end we should hexlify the values of dhcp request dictionary
        packet = b''.join(dhcp_request_dict.values())
        return packet

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

    """
    0           7           15         23          31
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |OP code(op)|  htype    |  hlen     |   hops    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           Transaction ID (xid)                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |     Seconds(sec)      |     Flags(flags)      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |        Client IP Address(ciaddr)              |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |         Your IP Address(yiaddr)               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |         Server IP Address(siaddr)             |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |         Gateway IP Address(giaddr)            |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |    Client Hardware Address(chaddr) (16bytes)  |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |         Server Name(sname) (64bytes)          |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |         Boot File Name(bname) (128bytes)      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | mcookie   | Options(options) (up to 214 bytes)|
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+"""

    def message(self):

        sname = []
        bname = []
        for i in range(192):
            if i < 64:
                sname.append(0)
            else:
                bname.append(0)

        packet = {'OP': bytes([0x01]),
                  'HTYPE': bytes([0x01]),
                  'HLEN': bytes([0x06]),
                  'HOPS': bytes([0x00]),
                  'XID': bytes(self.xid),
                  'SECS': bytes([0x00, 0x00]),
                  'FLAGS': bytes([0x00, 0x00]),
                  'CIADDR': bytes([0x00, 0x00, 0x00, 0x00]),
                  'YIADDR': bytes([0x00, 0x00, 0x00, 0x00]),
                  'SIADDR': bytes([0x00, 0x00, 0x00, 0x00]),
                  'GIADDR': bytes([0x00, 0x00, 0x00, 0x00]),
                  'CHADDR1': bytes(
                      [self.Mac_Address[0], self.Mac_Address[1], self.Mac_Address[2], self.Mac_Address[3]]),
                  'CHADDR2': bytes([self.Mac_Address[4], self.Mac_Address[5], 0x00, 0x00]),
                  'CHADDR3': bytes([0x00, 0x00, 0x00, 0x00]),
                  'CHADDR4': bytes([0x00, 0x00, 0x00, 0x00]),
                  'SName': bytes(sname),
                  'BName': bytes(bname),
                  'MCookie': bytes([0x63, 0x82, 0x53, 0x63]),
                  'option1': bytes([0, 0, 53, 1])}
        return packet


if __name__ == '__main__':
    mac_address = [0xff, 0xc1, 0x9a, 0xd6, 0x4d, 0x02]
    client = DHCP_Client(mac_address)
    client.run()
