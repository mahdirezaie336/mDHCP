import binascii
import socket as s
import struct


def ip_to_str(ip: bytes):
    return '.'.join([str(int(binascii.hexlify(ip[i: i+1]).decode(), 16)) for i in range(0, 4)])


def ips(start, end):
    start = struct.unpack('>I', s.inet_aton(start))[0]
    end = struct.unpack('>I', s.inet_aton(end))[0]
    return [s.inet_ntoa(struct.pack('>I', i)) for i in range(start, end)]


def convert_ip_to_bytes(ip_address: str) -> bytes:
    parts = ip_address.split('.')
    return b''.join([bytes([int(i)]) for i in parts])


def convert_mac_to_bytes(mac_address: str) -> bytes:
    parts = mac_address.split(':')
    return b''.join([bytes([int(i, 16)]) for i in parts])


print(ip_to_str(b'\xf1\xf2\x55\x13'))
