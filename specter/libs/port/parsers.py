# this file contains all the parser helper and functions


import re
import socket
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional

from .constants import NMAP_DB, PORT2SVC



# helper functions
def guess_svc_meta(port: int):
    """
    We guess the service through a chain
    we first  use PORT2SVC
    if that fails then we do /etc/services
    if that fails then we finally declare unknown
    and just returns none
    """
    if port in PORT2SVC:
        return PORT2SVC[port], "builtin"

    try:
        return socket.getservbyport(port, "tcp"), "system"
    except OSError:
        return "unknown", "none"


def guess_svc(port: int) -> str:
    svc, _source = guess_svc_meta(port)
    return svc



def parse_nmap_rows(out: str) -> Dict[int, Dict[str, str]]:
    # parses nmap text output:
    
    # 22/tcp   open   ssh     OpenSSH 8.4p1 Debian 5
    # 80/tcp   open   http    Apache httpd 2.4.46
    # 443/tcp  open   https   nginx 1.18.0
    
    # and returns the good dict structure
    
    rows: Dict[int, Dict[str, str]] = {}
    for line in out.splitlines():
        #   (\d+)                   - port number
        #   \/tcp                   - for only fetching TCP
        #   (open|closed|filtered)  - port state
        #   (\S+)                   - service name (first non-whitespace token)
        #   (.*)?                   - optional version/info string (rest of line)
        #   we skip everything that doesn't match
        m = re.match(
            r"^\s*(\d+)\/tcp\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?$", line
        )
        if m:
            port = int(m.group(1))
            rows[port] = {
                "port": port,
                "state": m.group(2),
                "svc": m.group(3),
                "info": (m.group(4) or "").strip(),
            }
    return rows

def _nmap_xml_info(service_el: Optional[ET.Element], port_el: ET.Element) -> str:
    # we take the nmap output and save it into our own format

    # xml already has the service metadata from the <service> element
    # (product name, version, extrainfo) and we also append
    # any nse script output found in child <script> elements

    info_parts: List[str] = []

    # we collect all the structured attribs from service element
    # we'll extract product, version, extrainfo
    if service_el is not None:
        for attr in ("product", "version", "extrainfo"):
            value = (service_el.get(attr) or "").strip()
            if value:
                info_parts.append(value)

    # then we append any NSE script output related
    # with this part (http-title, ssh-hotkeys, ssl-cert info)
    for script_el in port_el.findall("script"):
        output = (script_el.get("output") or "").strip()
        if output:
            info_parts.append(output)

    return " | ".join(info_parts)





def parse_nmap_row(out: str):
    
    # nmap outputs stuff like this:

    # PORT      STATE  SERVICE      VERSION
    # 22/tcp    open   ssh          OpenSSH 8.4p1 Debian 5

    # we parse the output according to this structure
    
    rows = parse_nmap_rows(out)
    if not rows:
        return None
    return rows[sorted(rows)[0]]

_top_ports_cache: Optional[List[int]] = None

def top_ports(n: int) -> List[int]:
    global _top_ports_cache
    if _top_ports_cache is None:
        _top_ports_cache = _load_top_ports(max_n=65535)
    if n >= len(_top_ports_cache):
        return list(_top_ports_cache)
    return _top_ports_cache[:n]


def _load_top_ports(max_n: int) -> List[int]:
    for db_path in NMAP_DB:
        p = Path(db_path)
        if not p.exists():
            continue

        scored = []
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            # skip blanks and comments
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            # need at least: port/proto, service, frequency
            # so we run a check to check if it has min 3 fields or not
            # and we only want TCP, so we discard other UDP ports
            if len(parts) < 3 or not parts[1].endswith("/tcp"):
                continue

            # extract port number
            # because in nmap it provides port number with a slash so we use it
            port_str = parts[1].split("/", 1)[0]
            if not port_str.isdigit():
                continue

            # frequency score (lower = more common)
            # and here if we get malformed lines
            try:
                score = float(parts[2])
            except ValueError:
                continue

            port = int(port_str)
            # we check for port 0 and anything >= 65536
            # because it ain't valid port number
            if 0 < port < 65536:
                scored.append((score, port))

        if scored:
            # we sort by descending by frequency (highest = most common first)
            scored.sort(key=lambda x: x[0], reverse=True)

            # dedupe
            # nmap db list same port multiple time
            # times with different services
            # here we only need one port once
            # so we just dedupe
            res, seen = [], set()
            for _score, port in scored:
                if port not in seen:
                    res.append(port)
                    seen.add(port)
                    if len(res) >= max_n:
                        break

            if res:
                return res

    return list(range(1, min(max_n, 65535) + 1))

def parse_ports(raw: Optional[str]) -> List[int]:
    # default to well-known ports (1-1024) if nothing given
    if not raw:
        return list(range(1, 1025))

    # we use set so we can dedupe the port numbers incase the user duplicates it
    # if user provides (80, 80-85) it'll dedupe 80
    out: set = set()

    # splits on commas
    # each chunk is either a single port or range
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue

        # range notation: 1-1024
        if "-" in chunk:
            left, right = chunk.split("-", 1)
            if not (left.strip().isdigit() and right.strip().isdigit()):
                continue

            a, b = int(left), int(right)
            # swap if reversed (1024-1 instead of 1-1024)
            # just so users dont have to order port ranges
            if a > b:
                a, b = b, a
            
            # >= 65536 is useless for port scanning
            out.update(p for p in range(a, b + 1) if 0 < p < 65536)
        else:
            # single port
            if chunk.isdigit():
                p = int(chunk)
                if 0 < p < 65536:
                    out.add(p)
                # non digit values ("http") are ignored
                # callers that want service name resolution should do
                # that before calling this function

    return sorted(out)

def _nmap_xml_svc_name(service_el: Optional[ET.Element], port: int) -> str:
    if service_el is None:
        return guess_svc(port)

    name = (service_el.get("name") or "").strip()
    tunnel = (service_el.get("tunnel") or "").strip()
    if tunnel and name:
        # nmap marks TLS-wrapped services with tunnel="tls"
        # return "tls/http" instead of just "http" so the caller
        # knows this port requires TLS.
        return f"{tunnel}/{name}"
    if name:
        return name
    return guess_svc(port)



def parse_nmap_xml_rows(xml_text: str) -> Dict[int, Dict[str, str]]:
    rows: Dict[int, Dict[str, str]] = {}
    if not xml_text.strip():
        return rows

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        # we bail because bad XML
        return rows

    for port_el in root.findall(".//host/ports/port"):
        # only catch tcp and we skip udp
        if (port_el.get("protocol") or "").strip().lower() != "tcp":
            continue

        port_id = (port_el.get("portid") or "").strip()
        if not port_id.isdigit():
            continue

        port = int(port_id)
        state_el = port_el.find("state")
        if state_el is None:
            continue

        state = (state_el.get("state") or "").strip()
        service_el = port_el.find("service")
        rows[port] = {
            "port": port,
            "state": state or "unknown",
            # we try nmap's service guess first
            # if that fails then we fallback
            # to our own
            "svc": _nmap_xml_svc_name(service_el, port),
            # product + version + nse script stuff altogether
            "info": _nmap_xml_info(service_el, port_el),
            # keep the xml raw
            # because we need to caller to
            # dig deeper just in case
            "raw": ET.tostring(port_el, encoding="unicode"),
        }

    return rows


def parse_nmap_ignored_counts(out: str) -> Dict[str, int]:
    counts = {"closed": 0, "filtered": 0}

    for line in out.splitlines():
        line = line.strip()
        # nmap says something like "Not shown: 997 closed tcp ports"
        # we grab those numbers
        if line.startswith("Not shown:"):
            for count, state in re.findall(
                r"(\d+)\s+(closed|filtered)\s+tcp\s+ports?", line
            ):
                counts[state] += int(count)
        else:
            # sometimes nmap says "All 1000 scanned ports on X are filtered"
            # we catch that too
            m = re.match(
                r"^All\s+(\d+)\s+scanned ports on .+ are (closed|filtered)\.?$",
                line,
            )
            if m:
                counts[m.group(2)] += int(m.group(1))

    return counts


def merge_nmap_rows(
    text_rows: Dict[int, Dict[str, str]],
    xml_rows: Dict[int, Dict[str, str]],
) -> Dict[int, Dict[str, str]]:
    merged: Dict[int, Dict[str, str]] = {}
    for port in sorted(set(text_rows) | set(xml_rows)):
        row = dict(xml_rows.get(port, {}))
        for key, value in text_rows.get(port, {}).items():
            if value not in (None, ""):
                row[key] = value
        merged[port] = row
    return merged


def grab_nmap_block(out: str, port: int) -> str:
    lines = out.splitlines()
    needle = f"{port}/tcp"
    idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith(needle):
            idx = i
            break
    if idx is None:
        return ""

    block = [lines[idx].strip()]
    for line in lines[idx + 1 :]:
        stripped = line.strip()
        if not stripped:
            break
        if re.match(r"^\d+/(tcp|udp)\s", stripped):
            break
        if stripped.startswith("Nmap scan report"):
            break
        if (
            stripped.startswith("|")
            or stripped.startswith("Service Info:")
            or stripped.startswith("Warning:")
        ):
            block.append(stripped)
    return "\n".join(block)
