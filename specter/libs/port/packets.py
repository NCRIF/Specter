# raw TCP packet builders and response parsers for the SYN scanner.
# everything here is hand-rolled wire format: we craft SYN segments (and, for
# IP_HDRINCL sends, the IP header too) and parse the raw replies that come back.


import random
import socket
import struct


def checksum(data):
    # internet checksum (RFC 1071): one's complement sum of 16-bit words, with
    # the carries folded back in, then inverted. used for both IP and TCP.
    if len(data) % 2 != 0:
        data += b"\x00"
    value = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    value = (value >> 16) + (value & 0xFFFF)    # fold the high 16 bits into the low
    value += value >> 16                        # fold once more in case that carried
    return ~value & 0xFFFF


def build_tcp_header(
    src_port, dst_port, seq, ack, flags
):
    # generic 20-byte TCP header with no options and a zero checksum.
    # data offset 5 = 5 words = 20 bytes.
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


def build_tcp_pseudo_header(src_ip, dst_ip, tcp_len):
    # the TCP checksum is computed over this pseudo-header prepended to the
    # segment: src/dst addr, a zero byte, the protocol number, and the TCP len.
    return struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,
        socket.IPPROTO_TCP,
        tcp_len,
    )


def build_syn_packet(src_ip, dst_ip, src_port, dst_port):
    # a 24-byte SYN: 20-byte header + a single MSS option. values are passed in
    # host order and "!" handles network byte order once.
    seq = random.randint(0, 0xFFFFFFFF)
    opts = struct.pack("!BBH", 2, 4, 1460)          # kind=2 (MSS), len=4, value=1460
    data_offset = ((20 + len(opts)) // 4) << 4      # header words, in the high nibble
    tcph = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, 0,                 # ack=0 on a SYN
        data_offset, 0x02,                          # flags 0x02 = SYN
        64240, 0, 0,                                # window, checksum placeholder, urgent
    ) + opts
    checksum_val = checksum(
        build_tcp_pseudo_header(src_ip, dst_ip, len(tcph)) + tcph
    )
    # splice the real checksum into bytes 16-18 of the header
    return tcph[:16] + struct.pack("!H", checksum_val) + tcph[18:]


def build_syn_with_ip(src_ip, dst_ip, src_port, dst_port):
    # full IP + TCP packet for IPPROTO_RAW sends (IP_HDRINCL=1), where the kernel
    # won't add an IP header for us. packed twice: once with checksum 0 to
    # compute the IP checksum, then again with it filled in.
    tcph = build_syn_packet(src_ip, dst_ip, src_port, dst_port)
    ident = random.randint(0, 0xFFFF)
    iph = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(tcph),                    # version 4 / IHL 5, tos 0, total length
        ident,
        0x4000, 64, socket.IPPROTO_TCP, 0,          # flags=DF, ttl 64, proto, checksum=0
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    ip_csum = checksum(iph)
    iph = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(tcph),
        ident,
        0x4000, 64, socket.IPPROTO_TCP, ip_csum,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    return iph + tcph


def parse_tcp_response(data):
    # returns (src_port, dst_port, flags) from a raw IP datagram. ihl is in 32-bit
    # words, so the TCP header starts ihl*4 bytes in. used by the single-host
    # scanner, which matches replies by our (unique) source port.
    try:
        ihl = (data[0] & 0x0F) * 4
        tcp_header = data[ihl : ihl + 20]
        if len(tcp_header) < 20:
            return None
        values = struct.unpack("!HHIIBBHHH", tcp_header)
        return values[0], values[1], values[5]      # src_port, dst_port, flags
    except Exception:
        return None


def parse_tcp_response_full(data):
    # like parse_tcp_response but also pulls the source IP (bytes 12-16 of the IP
    # header). the bulk engine matches replies by responder ip:port, so it never
    # depends on the source port and can reuse one port for the whole scan.
    try:
        ihl = (data[0] & 0x0F) * 4
        src_ip = socket.inet_ntoa(data[12:16])
        tcp_header = data[ihl : ihl + 20]
        if len(tcp_header) < 20:
            return None
        values = struct.unpack("!HHIIBBHHH", tcp_header)
        return src_ip, values[0], values[1], values[5]  # src_ip, src_port, dst_port, flags
    except Exception:
        return None
