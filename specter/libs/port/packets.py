# this file contains TCP scanner helpers


import random
import socket
import struct
from typing import Optional


def checksum(data: bytes) -> int:
    if len(data) % 2 != 0:
        data += b"\x00"
    value = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    value = (value >> 16) + (value & 0xFFFF)
    value += value >> 16
    return ~value & 0xFFFF


def build_tcp_header(
    src_port: int, dst_port: int, seq: int, ack: int, flags: int
) -> bytes:
    return struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        5 << 4,
        flags,
        socket.htons(65535),
        0,
        0,
    )


def build_tcp_pseudo_header(src_ip: str, dst_ip: str, tcp_len: int) -> bytes:
    return struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        tcp_len,
    )


def build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    seq = random.randint(0, 0xFFFFFFFF)
    tcp_header = build_tcp_header(src_port, dst_port, seq, 0, 0x02)
    checksum_val = checksum(
        build_tcp_pseudo_header(src_ip, dst_ip, len(tcp_header)) + tcp_header
    )
    return (
        struct.pack(
            "!HHIIBBH",
            src_port,
            dst_port,
            seq,
            0,
            5 << 4,
            0x02,
            socket.htons(65535),
        )
        + struct.pack("!H", checksum_val)
        + struct.pack("!H", 0)
    )


def parse_tcp_response(data: bytes) -> Optional[tuple]:
    try:
        ihl = (data[0] & 0x0F) * 4
        tcp_header = data[ihl : ihl + 20]
        if len(tcp_header) < 20:
            return None
        values = struct.unpack("!HHIIBBHHH", tcp_header)
        return values[0], values[1], values[5]
    except Exception:
        return None
