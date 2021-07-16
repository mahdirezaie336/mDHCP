import binascii
import socket as s
import struct


def ip_to_str(ip: bytes):
    return '.'.join([str(int(binascii.hexlify(ip[i: i+1]).decode(), 16)) for i in range(0, 4)])


def ips(start, end):
    start = struct.unpack('>I', s.inet_aton(start))[0]
    end = struct.unpack('>I', s.inet_aton(end))[0]
    return [s.inet_ntoa(struct.pack('>I', i)) for i in range(start, end)]


def ip_to_bytes(ip_address: str) -> bytes:
    parts = ip_address.split('.')
    return b''.join([bytes([int(i)]) for i in parts])


def mac_to_bytes(mac_address: str) -> bytes:
    parts = mac_address.split(':')
    return b''.join([bytes([int(i, 16)]) for i in parts])


def bin_to_int(number: bytes):
    return int(binascii.hexlify(number), 16)


def mac_to_str(mac_address: bytes):
    return ':'.join([binascii.hexlify(mac_address[i: i+1]).decode() for i in range(0, 6)])
