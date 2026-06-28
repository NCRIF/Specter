# this file contains all the constant values for port scanners




# colors we use throughout
CYAN = "cyan"
GREEN = "bright_green"
RED = "bright_red"
YELLOW = "yellow"
WHITE = "white"
DIM = "grey50"
DIMMER = "grey35"
DETAIL = "grey62"
BORDER = "grey23"
SVC_COL = "cyan"


# port definitions

WEB_PORTS = {
    80,
    81,
    88,
    2052,
    2082,
    2086,
    2095,
    3000,
    5000,
    8000,
    8008,
    8080,
    8888,
    9000,
    9090,
}

TLS_WEB_PORTS = {443, 2053, 2083, 2087, 2096, 4443, 8443, 9443}
SSH_PROBE_PORTS = {22}
HTTP_PROBE_TIMEOUT = 0.75 # time to wait for HTTP response per port
HTTP_PROBE_LIMIT = 16384  # max bytes that'll be read from the HTTP response
HTTP_TITLE_MAX = 120      # truncates the HTTP title if >120
SSH_BANNER_LIMIT = 256    # max banner bytes kept for SSH
LIVE_REFRESH_INTERVAL = 0.10 # update rate of terminal UI
SVC_PROGRESS_POLL = 0.05     # polling interval for service scan
LARGE_SCAN_PORT_THRESHOLD = 512 #  if requested ports ≥ this, the scanner switches to a "large scan" concurrency profile (wider sliding window, more retries)
WEB_SVC_HINTS = ("http", "https", "proxy", "www", "web")

HTTP_BLOCK_STATUSES = {403, 429, 503}


# port -> service name mapping
# most common ports, saves us from calling nmap for basic stuff
PORT2SVC = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    67: "dhcp",
    68: "dhcp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql-s",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
}


# nmap services db paths
# checked in order, first one found wins
NMAP_DB = [
    "/usr/share/nmap/nmap-services",
    "/usr/local/share/nmap/nmap-services",
]
