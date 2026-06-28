"""
top-level cli dispatcher for specter
"""

import argparse
import sys
from pathlib import Path
from textwrap import dedent

from . import __version__
from .scanner.port_scan import run_cli as run_port_scan
from .scanner.subdomain import run_cli as run_subdomain

ART = r"""
  _____ ____   ___    __ ______    ___  ____  
 / ___/|    \ /  _]  /  ]      |  /  _]|    \ 
(   \_ |  o  )  [_  /  /|      | /  [_ |  D  )
 \__  ||   _/    _]/  / |_|  |_||    _]|    / 
 /  \ ||  | |   [_/   \_  |  |  |   [_ |    \ 
 \    ||  | |     \     | |  |  |     ||  .  \
  \___||__| |_____|\____| |__|  |_____||__|\_|

                                by - X3r0Day | x3r0day.me
"""

SCAN_CMDS = {"scan", "portscan"}
SUB_CMDS = {"subdomain", "sub", "enum"}


def build_parser(prog = None):
    tool = prog or "specter"
    ap = argparse.ArgumentParser(
        prog=tool,
        description="Subdomain enumeration and TCP port scanning.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent(
            f"""\
            Aliases:
              scan: portscan
              subdomain: sub, enum

            Shortcut:
              {tool} <target> [opts]    same as {tool} scan <target> [opts]
            """
        ),
    )
    ap.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subs = ap.add_subparsers(title="commands", metavar="<command>")
    subs.add_parser("scan", help="async tcp port scanner")
    subs.add_parser("subdomain", help="async subdomain enumerator")
    subs.add_parser("banner", help="show the project banner")
    return ap


def _help_cmd(argv, ap, tool):
    if not argv:
        ap.print_help()
        return 0

    cmd = argv[0]
    if cmd in SCAN_CMDS:
        return run_port_scan(["--help"], prog=f"{tool} {cmd}")
    if cmd in SUB_CMDS:
        return run_subdomain(["--help"], prog=f"{tool} {cmd}")
    if cmd == "banner":
        sys.stdout.write(f"usage: {tool} banner\n")
        return 0

    sys.stderr.write(f"{tool}: error: unknown command '{cmd}'\n")
    return 2


def main(argv = None, prog = None):
    argv = list(sys.argv[1:] if argv is None else argv)
    tool = prog or Path(sys.argv[0]).name or "specter"
    ap = build_parser(prog=tool)

    if not argv:
        print(ART)
        ap.print_help()
        return 0

    cmd = argv[0]
    if cmd in {"-h", "--help"}:
        ap.print_help()
        return 0
    if cmd == "--version":
        print(f"{tool} {__version__}")
        return 0
    if cmd == "help":
        return _help_cmd(argv[1:], ap, tool)
    if cmd == "banner":
        print(ART)
        return 0
    if cmd in SCAN_CMDS:
        return run_port_scan(argv[1:], prog=f"{tool} {cmd}")
    if cmd in SUB_CMDS:
        return run_subdomain(argv[1:], prog=f"{tool} {cmd}")

    return run_port_scan(argv, prog=f"{tool} scan")


# compatibility aliases
BANNER = ART
SCAN_ALIASES = SCAN_CMDS
SUBDOMAIN_ALIASES = SUB_CMDS
mk_parser = build_parser
_help_for = _help_cmd
