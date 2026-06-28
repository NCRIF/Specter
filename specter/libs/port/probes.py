# this file contains service-probe and TLS formatting helpers


import asyncio
import re
from datetime import datetime

from .builders import _clean_text
from .constants import (
    HTTP_TITLE_MAX,
    SSH_PROBE_PORTS,
    TLS_WEB_PORTS,
    WEB_PORTS,
    WEB_SVC_HINTS,
)


def should_try_http_probe(port, guessed_svc, guess_source):
    low = guessed_svc.lower()
    if port in WEB_PORTS or port in TLS_WEB_PORTS:
        return True
    if port in SSH_PROBE_PORTS or low == "ssh":
        return False
    if any(hint in low for hint in WEB_SVC_HINTS):
        return True
    if port >= 1024 and guess_source != "builtin":
        return True
    return False


def has_http_probe_signal(res):
    if res.err is not None:
        return False
    raw = (res.raw or "").lstrip().lower()
    info = (res.info or "").lower()
    return (
        raw.startswith("http/")
        or "http/" in info
        or "title:" in info
        or "server:" in info
        or "cf-ray" in info
        or "redirect" in info
    )


def extract_title(text):
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return _clean_text(match.group(1), HTTP_TITLE_MAX)


def _flatten_cert_name(parts):
    flat = {}
    for item in parts or ():
        for key, value in item:
            flat[key] = value
    return flat


def _fmt_cert_date(raw):
    if not raw:
        return ""
    normalized = re.sub(r"\s+", " ", raw.strip())
    try:
        return datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z").strftime(
            "%Y-%m-%d"
        )
    except ValueError:
        return normalized


def tls_cert_bits(cert):
    if not cert:
        return []

    bits = []
    subject = _flatten_cert_name(cert.get("subject"))
    common_name = subject.get("commonName", "")
    if common_name:
        bits.append(f"TLS CN: {_clean_text(common_name, 80)}")

    san = cert.get("subjectAltName") or []
    dns_names = [value for kind, value in san if kind.lower() == "dns"]
    if dns_names:
        first = _clean_text(dns_names[0], 80)
        if len(dns_names) > 1:
            bits.append(f"TLS SAN: {first} (+{len(dns_names) - 1})")
        elif first != common_name:
            bits.append(f"TLS SAN: {first}")

    expires = _fmt_cert_date(str(cert.get("notAfter", "")).strip())
    if expires:
        bits.append(f"TLS Expires: {expires}")
    return bits


async def http_get_response(
    reader,
    writer,
    host,
    timeout,
):
    request = (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"Accept: text/html,*/*;q=0.9\r\n"
        f"Accept-Encoding: identity\r\n"
        f"User-Agent: X3r0Day-Specter/0.1\r\n\r\n"
    )
    writer.write(request.encode())
    await writer.drain()
    try:
        raw = await asyncio.wait_for(reader.read(4096), timeout=timeout)
    except Exception:
        raw = b""
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
    except Exception:
        pass
    return raw


def parse_http_banner(raw, port):
    svc_name = "https" if port == 443 else "http"
    status_code = 0
    if not raw:
        return svc_name, "", status_code
    text = raw.decode(errors="ignore")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n") if head else text.split("\r\n")
    parts = []
    if lines and lines[0].startswith("HTTP/"):
        parts.append(lines[0])
        tok = lines[0].split()
        if len(tok) >= 2 and tok[1].isdigit():
            status_code = int(tok[1])
    for line in lines[1:]:
        low = line.lower()
        if low.startswith("server:"):
            srv = line.split(":", 1)[1].strip()
            parts.append(f"Server: {srv}")
            srv_low = srv.lower()
            if "cloudflare" in srv_low:
                svc_name = "cloudflare"
            elif "nginx" in srv_low:
                svc_name = "nginx"
            elif "apache" in srv_low:
                svc_name = "apache"
        elif low.startswith("cf-ray:"):
            parts.append("CF-Ray")
        elif low.startswith("location:"):
            parts.append("Redirect")
    title = extract_title(body) if body else ""
    if title:
        parts.append(f"Title: {title}")
    return svc_name, " | ".join(parts), status_code

