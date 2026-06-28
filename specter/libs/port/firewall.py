# firewall guard for SYN scanning.
#
# while a SYN scan runs we add an INPUT DROP for replies arriving at our scan
# source port. this stops the kernel from RSTing the half-open connection and
# from creating conntrack state, while the AF_PACKET capture still sees every
# packet (it runs below netfilter).
# all rules are removed on every exit path.

import atexit
import os
import shutil
import signal
import subprocess

_active_ports = set()
_installed = False


def fw_rule(action, dport):
    cmd = [
        "iptables", action, "INPUT", "-p", "tcp",
        "--dport", str(dport), "-j", "DROP",
    ]
    try:
        subprocess.run(cmd, capture_output=True, timeout=10)
    except Exception:
        pass


def fw_cleanup():
    # remove every rule we added. block SIGINT during removal so repeated
    # Ctrl+C can't abort the cleanup and leave a rule behind. idempotent.
    if not _active_ports:
        return
    try:
        prev = signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (ValueError, OSError):
        prev = None
    try:
        while _active_ports:
            fw_rule("-D", _active_ports.pop())
    finally:
        if prev is not None:
            try:
                signal.signal(signal.SIGINT, prev)
            except (ValueError, OSError):
                pass


def fw_install_guard():
    # ensure cleanup runs on every exit path:
    #   - normal return / unhandled exception   -> finally block in the scanner
    #   - process exit                          -> atexit
    #   - SIGINT (Ctrl+C)                       -> default KeyboardInterrupt
    #                                              unwinds through finally + atexit
    #   - SIGTERM / SIGHUP                      -> converted to SystemExit, which
    #                                              also unwinds finally + atexit
    # the signal handler does NO real work (no subprocess) to avoid deadlocking
    # inside the asyncio event loop. it only raises.
    global _installed
    if _installed:
        return
    _installed = True
    atexit.register(fw_cleanup)

    def _term_handler(signum, frame):
        raise SystemExit(128 + signum)

    for s in (signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(s, _term_handler)
        except (ValueError, OSError):
            pass  # not main thread, atexit + finally still cover us


def fw_add(dport):
    if os.geteuid() != 0:
        return False
    if shutil.which("iptables") is None:
        return False
    fw_install_guard()
    _active_ports.add(dport)
    fw_rule("-A", dport)
    return True
