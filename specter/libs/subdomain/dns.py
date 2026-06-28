# this file contains all the DNS related functions

import asyncio
import re
import secrets
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List

from .constants import (
    DNS_CNAME_MAX,
    DNS_IN,
    DNS_PKT_MAX,
    DNS_PORT,
    DNS_QTYPE_A,
    DNS_QTYPE_AAAA,
    DNS_QTYPE_CNAME,
    DNS_TO,
    DNS_TRIES,
)


class DnsError(RuntimeError):
    pass


class DnsFallback(RuntimeError):
    pass


@dataclass
class DnsResult:
    ans: List[str]
    fallback: bool = False


def load_nameservers():
    conf = Path("/etc/resolv.conf")
    if not conf.exists():
        return []
    nameservers = []
    for line in conf.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or not line.startswith("nameserver"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            nameservers.append(parts[1])
    return nameservers


def dns_addr(nameserver):
    family = socket.AF_INET6 if ":" in nameserver else socket.AF_INET
    if family == socket.AF_INET6:
        return family, (nameserver, DNS_PORT, 0, 0)
    return family, (nameserver, DNS_PORT)


def encode_name(name):
    labels = [label for label in name.strip(".").split(".") if label]
    return (
        b"".join(
            len(label.encode("idna")).to_bytes(1, "big") + label.encode("idna")
            for label in labels
        )
        + b"\x00"
    )


def decode_name(packet, offset):
    labels = []
    current = offset
    next_offset = None
    seen = set()
    while True:
        if current >= len(packet):
            raise DnsError("dns name exceeds packet bounds")
        length = packet[current]
        if length & 0xC0 == 0xC0:
            if current + 1 >= len(packet):
                raise DnsError("dns pointer truncated")
            pointer = ((length & 0x3F) << 8) | packet[current + 1]
            if pointer in seen:
                raise DnsError("dns pointer loop")
            seen.add(pointer)
            if next_offset is None:
                next_offset = current + 2
            current = pointer
            continue
        if length == 0:
            current += 1
            break
        current += 1
        if current + length > len(packet):
            raise DnsError("dns label exceeds packet bounds")
        labels.append(packet[current : current + length].decode("ascii", errors="ignore"))
        current += length
    return ".".join(labels), next_offset if next_offset is not None else current


def make_query(name, qtype):
    txid = secrets.randbelow(65536)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack("!HH", qtype, DNS_IN)
    return txid, header + question


def parse_response(
    packet, txid, qtype
):
    if len(packet) < 12:
        raise DnsError("dns packet too short")
    response_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", packet[:12]
    )
    if response_id != txid:
        raise DnsError("dns txid mismatch")
    truncated = bool(flags & 0x0200)
    rcode = flags & 0x000F
    offset = 12
    for _ in range(qdcount):
        _, offset = decode_name(packet, offset)
        offset += 4
        if offset > len(packet):
            raise DnsError("dns question truncated")

    answers = []
    cnames = []
    for _ in range(ancount):
        _, offset = decode_name(packet, offset)
        if offset + 10 > len(packet):
            raise DnsError("dns answer header truncated")
        rr_type, rr_class, _ttl, rdlen = struct.unpack(
            "!HHLH", packet[offset : offset + 10]
        )
        offset += 10
        if offset + rdlen > len(packet):
            raise DnsError("dns rdata truncated")
        rdata_offset = offset
        rdata = packet[offset : offset + rdlen]
        offset += rdlen
        if rr_class != DNS_IN:
            continue
        if rr_type == qtype:
            if qtype == DNS_QTYPE_A and rdlen == 4:
                answers.append(socket.inet_ntop(socket.AF_INET, rdata))
            elif qtype == DNS_QTYPE_AAAA and rdlen == 16:
                answers.append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif rr_type == DNS_QTYPE_CNAME:
            cname, _ = decode_name(packet, rdata_offset)
            if cname:
                cnames.append(cname.lower().strip("."))
    return answers, cnames, truncated, rcode


class DnsResolver:
    def __init__(self, timeout = DNS_TO):
        self._to = timeout
        self._ns = load_nameservers()

    async def _query(self, nameserver, name, qtype):
        loop = asyncio.get_running_loop()
        txid, query = make_query(name, qtype)
        family, addr = dns_addr(nameserver)
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_sendto(sock, query, addr)
            packet, _ = await asyncio.wait_for(
                loop.sock_recvfrom(sock, DNS_PKT_MAX), timeout=self._to
            )
        finally:
            sock.close()

        answers, cnames, truncated, rcode = parse_response(packet, txid, qtype)
        if truncated:
            return DnsResult([], fallback=True)
        if answers:
            return DnsResult(answers)
        if cnames:
            return DnsResult(cnames)
        if rcode in {2, 5}:
            return DnsResult([], fallback=True)
        return DnsResult([])

    async def _lookup(self, name, qtype, depth = 0):
        if depth > DNS_CNAME_MAX or not self._ns:
            return DnsResult([], fallback=True)
        need_fallback = False
        for nameserver in self._ns:
            for _ in range(DNS_TRIES):
                try:
                    result = await self._query(nameserver, name, qtype)
                except (OSError, asyncio.TimeoutError, DnsError):
                    need_fallback = True
                    continue
                if result.ans:
                    if qtype in {DNS_QTYPE_A, DNS_QTYPE_AAAA} and all(
                        not re.match(r"^\d+\.\d+\.\d+\.\d+$", value) and ":" not in value
                        for value in result.ans
                    ):
                        return await self._lookup(result.ans[0], qtype, depth + 1)
                    return result
                if result.fallback:
                    need_fallback = True
                    continue
                return result
        return DnsResult([], fallback=need_fallback)

    async def resolve(self, host):
        ipv4, ipv6 = await asyncio.gather(
            self._lookup(host, DNS_QTYPE_A),
            self._lookup(host, DNS_QTYPE_AAAA),
        )
        if ipv4.ans:
            return ipv4.ans[0]
        if ipv6.ans:
            return ipv6.ans[0]
        if ipv4.fallback or ipv6.fallback:
            raise DnsFallback(host)
        return ""
