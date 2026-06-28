# this file contains all the parser helper and functions


import argparse
from pathlib import Path


def build_parser(prog = None):
    parser = argparse.ArgumentParser(
        prog=prog,
        description="async subdomain enumerator: passive sources + async port scans + scraping",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("domain", help="target apex domain  (e.g. example.com)")
    parser.add_argument("-K", "--shodan-key", default=None, help="shodan api key")
    parser.add_argument(
        "-b",
        "--brute",
        action="store_true",
        help="brute force common subdomain prefixes after passive enumeration",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        type=Path,
        default=None,
        help="custom wordlist file for brute force (one word per line)",
    )
    parser.add_argument(
        "-N",
        "--no-port-scan",
        "--no-nmap",
        dest="no_nmap",
        action="store_true",
        help="skip web port scanning on resolved subdomains",
    )
    parser.add_argument(
        "-W", "--no-scrape", action="store_true", help="skip http page scraping"
    )
    parser.add_argument("-M", "--nmap-args", default="", help=argparse.SUPPRESS)
    parser.add_argument(
        "-c",
        "--resolve-concurrency",
        type=int,
        default=200,
        help="concurrent dns resolution limit (default: 200)",
    )
    parser.add_argument(
        "-C",
        "--scan-concurrency",
        "--nmap-concurrency",
        dest="nmap_concurrency",
        type=int,
        default=30,
        help="parallel per-host port scan limit (default: 30)",
    )
    parser.add_argument(
        "-t",
        "--http-timeout",
        type=float,
        default=8.0,
        help="http scrape timeout in seconds (default: 8.0)",
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", help="show extra error detail and tracebacks"
    )
    parser.add_argument(
        "-o",
        "--out",
        default=None,
        help="write results to file (.html default, .json/.csv by suffix)",
    )
    parser.add_argument(
        "-v", action="count", default=0, help="show extra source/report detail"
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress scan-time banners and progress chatter",
    )
    return parser
