import binascii
import socket as s
import struct


def ip_to_str(ip: bytes) -> str:
    """ Converts the IP address from bytes to string.
        Example:
            b'\xc0\xa8\x01\x01'  -->  192.168.1.1
        :param ip The IP address in bytes type
        :returns The IP address in string type
        """
    return '.'.join([str(int(binascii.hexlify(ip[i: i+1]).decode(), 16)) for i in range(0, 4)])


def ips(start: str, end: str) -> list[str]:
    """ Gets a range of IP address by start and end bounds of range.
        :param start The start of range
        :param end The end of range
        :returns A list of IP addresses
        """
    start = struct.unpack('>I', s.inet_aton(start))[0]
    end = struct.unpack('>I', s.inet_aton(end))[0]
    return [s.inet_ntoa(struct.pack('>I', i)) for i in range(start, end)]


def ip_to_bytes(ip_address: str) -> bytes:
    """ Converts the IP address from bytes to string.
        Example:
            192.168.1.1   -->   b'\xc0\xa8\x01\x01'
        """
    parts = ip_address.split('.')
    return b''.join([bytes([int(i)]) for i in parts])


def mac_to_bytes(mac_address: str) -> bytes:
    """ Converts the MAC address from string to bytes.
        Example:
            14:cc:20:f3:8b:ea   -->   b'\x14\xcc \xf3\x8b\xea'
        """
    parts = mac_address.split(':')
    return b''.join([bytes([int(i, 16)]) for i in parts])


def bin_to_int(number: bytes) -> int:
    """ Converts binary to integer. """
    return int(binascii.hexlify(number), 16)


def mac_to_str(mac_address: bytes):
    """ Converts the MAC address from bytes to string.
        Example:
            b'\x14\xcc \xf3\x8b\xea'   -->   14:cc:20:f3:8b:ea
        """
    return ':'.join([binascii.hexlify(mac_address[i: i+1]).decode() for i in range(0, 6)])


def bin_to_str(binary: bytes):
    """ Converts binary to string """
    return binascii.hexlify(binary).decode()
