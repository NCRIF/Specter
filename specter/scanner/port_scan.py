# async tcp port scanner & service detection


import asyncio
import getpass
import ipaddress
import io
import json
import os
import random
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import select
from rich.console import Console
from rich.live import Live
from rich.progress import Progress
from rich.text import Text

from ..core.results import ScanHit
from ..libs.port.builders import (
    _clean_text,
    build_live_panel,
    build_parser,
    build_scan_html,
    console as port_console,
    hdr as port_hdr,
    mk_prog as port_mk_prog,
    open_tbl as port_open_tbl,
    out_mode as port_out_mode,
    scan_csv as port_scan_csv,
    show_multi_sum as port_show_multi_sum,
    show_scan as port_show_scan,
    sum_tbl as port_sum_tbl,
)
from ..libs.port.constants import (
    CYAN,
    DIM,
    DIMMER,
    GREEN,
    HTTP_BLOCK_STATUSES,
    HTTP_PROBE_TIMEOUT,
    LARGE_SCAN_PORT_THRESHOLD,
    LIVE_REFRESH_INTERVAL,
    RED,
    SSH_BANNER_LIMIT,
    SSH_PROBE_PORTS,
    SVC_COL,
    SVC_PROGRESS_POLL,
    TLS_WEB_PORTS,
    WHITE,
    YELLOW,
)
from ..libs.port.models import Cfg, ScanOut, SvcInfo
from ..libs.port.network import DynamicSemaphore, sock_addr
from ..libs.port.packets import (
    build_syn_packet,
    parse_tcp_response,
)
from ..libs.port.parsers import (
    grab_nmap_block,
    guess_svc,
    guess_svc_meta,
    merge_nmap_rows,
    parse_nmap_ignored_counts,
    parse_nmap_rows,
    parse_nmap_xml_rows,
    parse_ports,
    top_ports,
)
from ..libs.port.probes import (
    has_http_probe_signal,
    http_get_response,
    parse_http_banner,
    should_try_http_probe,
    tls_cert_bits as _tls_cert_bits,
)
from .bulk import scan_targets_parallel, scan_with_agents


# all of the contsants are saved in ../port/constants.py
# edit constants.py to configure default values

# all the helpers are located in ../libs/port

# output goes here
console = port_console

HTTP_SSL_CTX = ssl.create_default_context()
HTTP_SSL_CTX.check_hostname = False
HTTP_SSL_CTX.verify_mode = ssl.CERT_NONE


hdr = port_hdr
mk_prog = port_mk_prog
open_tbl = port_open_tbl
sum_tbl = port_sum_tbl
show_scan = port_show_scan
show_multi_sum = port_show_multi_sum
_out_mode = port_out_mode
_scan_csv = port_scan_csv


class Scanner:
    def __init__(self, cfg):
        self.cfg = cfg
        self._s_sem = asyncio.Semaphore(cfg.s_conc)
        self._lock = asyncio.Lock()
        self._http_probe_blocked = False
        self._target_is_ip = self._is_ip_literal(cfg.target)
        self._raw_sock = None
        self._src_ip = None
        self._resolved_ip = None
        self._resolved_candidates = []
        self._reset_scan_state()

        # SYN scan receiver state
        self._syn_receiver_task = None
        self._syn_tracking = {}  # src_port -> (dst_port, event, result_holder, started_at)
        self._syn_tracking_lock = asyncio.Lock()
        self._syn_receiver_lock = asyncio.Lock()
        self._syn_receiver_running = False
        self._syn_sock_ready = False

    def _ensure_syn_socket(self, target_ip):
        if self._syn_sock_ready:
            return
        if not self.cfg.syn_scan:
            return
        try:
            self._raw_sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
            )
            self._raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
            self._raw_sock.setblocking(False)
            # discover source IP via a throwaway UDP connect
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                test_sock.connect((target_ip, 80))
                self._src_ip = test_sock.getsockname()[0]
                test_sock.close()
            except Exception:
                self._src_ip = "0.0.0.0"
            self._syn_sock_ready = True
        except PermissionError:
            pass

    def _reset_scan_state(self):
        self._svc_tasks = []
        self._svc_results = {}
        self._svc_scheduled = set()
        self._svcs = []
        self._st = {p: "pending" for p in self.cfg.ports}
        self._tested = 0
        self._open = 0
        self._closed = 0
        self._filtered = 0
        self._svc_started = 0
        self._svc_done = 0
        self._svc_failed = 0
        self._open_ports = []
        self._live_next_refresh = 0.0

    # mark port as started service scan
    async def _mark_svc_start(self, port):
        async with self._lock:
            self._svc_started += 1
            self._st[port] = "scanning"

    # mark service scan as done
    async def _mark_svc_done(self, port, ok):
        async with self._lock:
            self._svc_done += 1
            self._st[port] = "done" if ok else "failed"
            if not ok:
                self._svc_failed += 1

    async def _mark_svc_batch_start(self, ports):
        async with self._lock:
            for port in ports:
                self._svc_started += 1
                self._st[port] = "scanning"

    async def _mark_svc_batch_done(self, results, ports):
        async with self._lock:
            for port in ports:
                res = results.get(port)
                ok = True if res is None else res.ok
                self._svc_done += 1
                self._st[port] = "done" if ok else "failed"
                if not ok:
                    self._svc_failed += 1

    def _is_ip_literal(self, host):
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _ordered_ports(self):
        if len(self.cfg.ports) <= 100:
            return list(self.cfg.ports)
        common = set(top_ports(min(1000, len(self.cfg.ports))))
        priority = [p for p in self.cfg.ports if p in common]
        rest = [p for p in self.cfg.ports if p not in common]
        return priority + rest

    def _scan_profile(self):
        port_count = len(self.cfg.ports)

        if self.cfg.stealth:
            return {
                "window": max(1, min(self.cfg.c_conc, 96)),
                "max_window": max(1, min(self.cfg.c_conc, 192)),
                "min_window": max(1, min(self.cfg.c_conc, 24)),
                "increase": 4,
                "max_retries": self.cfg.max_retries,
                "retry_budget": max(8, min(port_count // 8, 64)),
                "timeout_floor": min(self.cfg.c_to, 0.50),
            }

        if port_count < LARGE_SCAN_PORT_THRESHOLD:
            start_window = max(1, min(self.cfg.c_conc, max(128, min(port_count, 512))))
            return {
                "window": start_window,
                "max_window": max(start_window, self.cfg.c_conc),
                "min_window": max(64, min(start_window, 256)),
                "increase": 16,
                "max_retries": self.cfg.max_retries,
                "retry_budget": max(8, min(port_count // 4, 64)),
                "timeout_floor": min(self.cfg.c_to, 0.35),
            }

        if port_count >= 32768:
            start_window = max(1, min(self.cfg.c_conc, 512))
            max_window = max(start_window, self.cfg.c_conc)
            min_window = max(128, min(start_window, 256))
            return {
                "window": start_window,
                "max_window": max_window,
                "min_window": min_window,
                "increase": 32,
                "max_retries": self.cfg.max_retries,
                "retry_budget": max(64, min(port_count // 32, 1024)),
                "timeout_floor": min(self.cfg.c_to, 0.75),
            }

        if port_count >= LARGE_SCAN_PORT_THRESHOLD:
            start_window = max(1, min(self.cfg.c_conc, max(256, min(port_count, 768))))
            max_window = max(start_window, self.cfg.c_conc)
            min_window = max(96, min(start_window, 256))
            return {
                "window": start_window,
                "max_window": max_window,
                "min_window": min_window,
                "increase": 32,
                "max_retries": self.cfg.max_retries,
                "retry_budget": max(32, min(port_count // 16, 256)),
                "timeout_floor": min(self.cfg.c_to, 0.50),
            }

        start_window = max(1, min(self.cfg.c_conc, max(128, min(port_count, 512))))
        return {
            "window": start_window,
            "max_window": max(start_window, self.cfg.c_conc),
            "min_window": max(64, min(start_window, 256)),
            "increase": 16,
            "max_retries": self.cfg.max_retries,
            "retry_budget": max(8, min(port_count // 4, 64)),
            "timeout_floor": min(self.cfg.c_to, 0.35),
        }

    async def _maybe_refresh_live(
        self,
        live,
        prog,
        live_ports,
        force = False,
    ):
        # quiet mode: skip lock and Rich rendering
        if self.cfg.quiet:
            return
        now = time.perf_counter()
        async with self._lock:
            if not force and now < self._live_next_refresh:
                return
            self._live_next_refresh = now + LIVE_REFRESH_INTERVAL
        live.update(build_live_panel(prog, live_ports, self.cfg.target))

    async def _finish_port(
        self,
        port,
        state,
        prog,
        tid,
        live_ports,
        live,
    ):
        svc = guess_svc(port)
        announce_open = False
        queue_svc = False

        async with self._lock:
            current = self._st.get(port, "pending")
            if current not in {"pending", "retrying"}:
                return

            self._tested += 1
            self._st[port] = state

            if state == "open":
                self._open += 1
                self._open_ports.append(port)
                live_ports.append(port)
                announce_open = True
                queue_svc = self.cfg.svc_on and not self.cfg.aggr_on
            elif state == "filtered":
                self._filtered += 1
            else:
                self._closed += 1

            prog.advance(tid)

        if announce_open:
            live.console.print(
                Text.assemble(
                    ("  ◉ ", GREEN),
                    (f"{port:>5}/tcp", f"bold {WHITE}"),
                    ("  →  ", DIM),
                    (svc, SVC_COL),
                ),
            )

        if queue_svc:
            await self._queue_service_detection(port)

    def _finish_port_sync(self, port, state, live_ports):
        if state == "open":
            self._open += 1
            self._open_ports.append(port)
            live_ports.append(port)
        elif state == "filtered":
            self._filtered += 1
        else:
            self._closed += 1
        self._tested += 1
        self._st[port] = state

    async def _run_nmap(self, base_cmd):
        cmd = list(base_cmd)
        sudo_in = None

        if self.cfg.sudo_pw is not None:
            cmd = ["sudo", "-S", "-p", ""] + cmd
            sudo_in = (self.cfg.sudo_pw + "\n").encode()

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if sudo_in is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out_b, err_b = await proc.communicate(input=sudo_in)
        return (
            proc.returncode,
            (out_b or b"").decode(errors="replace"),
            (err_b or b"").decode(errors="replace").strip(),
            " ".join(cmd),
        )

    async def _nmap_batch(self, host, ports):
        if not ports:
            return []

        t0 = time.perf_counter()
        xml_path = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix="x3r0day-nmap-",
                suffix=".xml",
                delete=False,
                dir="/tmp",
            ) as tmp:
                xml_path = tmp.name
        except OSError:
            xml_path = None

        base_cmd = [
            "nmap",
            "-Pn",
            "-n",
        ]
        if xml_path:
            base_cmd.extend(["-oX", xml_path])
        base_cmd.extend(
            [
                "-p",
                ",".join(str(p) for p in ports),
            ]
        )
        base_cmd.extend(self.cfg.n_args)
        base_cmd.append(host)

        try:
            rc, out, err, n_cmd = await self._run_nmap(base_cmd)
        except FileNotFoundError:
            elapsed = round(time.perf_counter() - t0, 3)
            return [
                SvcInfo(
                    port=port,
                    ok=False,
                    state="scan_failed",
                    svc="unknown",
                    info="nmap not found in PATH",
                    elapsed=elapsed,
                    n_cmd=" ".join(base_cmd),
                    raw="",
                    err="nmap not found in PATH",
                )
                for port in ports
            ]
        finally:
            xml_out = ""
            if xml_path:
                try:
                    xml_out = Path(xml_path).read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    xml_out = ""
                try:
                    Path(xml_path).unlink(missing_ok=True)
                except OSError:
                    pass

        text_rows = parse_nmap_rows(out)
        xml_rows = parse_nmap_xml_rows(xml_out)
        rows = merge_nmap_rows(text_rows, xml_rows)
        elapsed = round(time.perf_counter() - t0, 3)
        results = []

        for port in sorted(ports):
            parsed = rows.get(port)
            block = grab_nmap_block(out, port)
            xml_block = xml_rows.get(port, {}).get("raw", "")
            if parsed:
                results.append(
                    SvcInfo(
                        port=port,
                        ok=rc == 0,
                        state=parsed["state"],
                        svc=parsed["svc"],
                        info=parsed["info"] or block,
                        elapsed=elapsed,
                        n_cmd=n_cmd,
                        raw=block or xml_block or out or xml_out,
                        err=err or None,
                    )
                )
            else:
                results.append(
                    SvcInfo(
                        port=port,
                        ok=rc == 0,
                        state="open",
                        svc=guess_svc(port),
                        info=block or "nmap completed but no port row parsed",
                        elapsed=elapsed,
                        n_cmd=n_cmd,
                        raw=block or xml_block or out or xml_out,
                        err=err or None,
                    )
                )

        return results

    async def _store_svc_result(self, res):
        async with self._lock:
            self._svc_results[res.port] = res

    async def _store_svc_batch_results(self, results):
        async with self._lock:
            for res in results:
                self._svc_results[res.port] = res

    async def _queue_service_detection(self, port):
        if not self.cfg.svc_on or self._resolved_ip is None:
            return

        async with self._lock:
            if port in self._svc_scheduled:
                return

            self._svc_scheduled.add(port)
            task = asyncio.create_task(self._svc_worker_basic(self._resolved_ip, port))
            self._svc_tasks.append(task)

    async def _queue_service_detection_batch(
        self, host, ports
    ):
        if not self.cfg.svc_on or self._resolved_ip is None or not ports:
            return

        async with self._lock:
            batch_ports = [port for port in ports if port not in self._svc_scheduled]
            if not batch_ports:
                return

            self._svc_scheduled.update(batch_ports)
            task = asyncio.create_task(
                self._svc_worker_aggressive_batch(host, sorted(batch_ports))
            )
            self._svc_tasks.append(task)

    async def _svc_worker_basic(self, ip, port):
        await self._mark_svc_start(port)
        try:
            async with self._s_sem:
                res = await self._basic(ip, port)
        except Exception as err:
            res = SvcInfo(
                port=port,
                ok=True,
                state="open",
                svc=guess_svc(port),
                info=f"light probe worker failed: {str(err)[:60]}",
                elapsed=0.0,
                n_cmd="",
                raw="",
                err=str(err),
            )
        await self._store_svc_result(res)
        await self._mark_svc_done(port, res.ok)

    async def _svc_worker_aggressive_batch(self, host, ports):
        await self._mark_svc_batch_start(ports)
        try:
            async with self._s_sem:
                results = await self._nmap_batch(host, ports)
        except Exception as err:
            msg = f"nmap service scan failed: {str(err)[:60]}"
            results = [
                SvcInfo(
                    port=port,
                    ok=True,
                    state="open",
                    svc=guess_svc(port),
                    info=msg,
                    elapsed=0.0,
                    n_cmd="",
                    raw="",
                    err=str(err),
                )
                for port in ports
            ]

        by_port = {res.port: res for res in results}
        await self._store_svc_batch_results(results)
        await self._mark_svc_batch_done(by_port, ports)

    async def _nmap_discover(
        self,
        host,
        ports,
        prog,
        tid,
        live,
        live_ports,
    ):
        base_cmd = [
            "nmap",
            "-Pn",
            "-n",
            "-sS",
            "-p",
            ",".join(str(p) for p in ports),
            host,
        ]

        try:
            rc, out, err, _n_cmd = await self._run_nmap(base_cmd)
        except FileNotFoundError:
            return "nmap not found in PATH"

        rows = parse_nmap_rows(out)
        ignored = parse_nmap_ignored_counts(out)
        open_ports = sorted(
            port for port, row in rows.items() if row["state"] == "open"
        )
        shown_closed = sum(1 for row in rows.values() if row["state"] == "closed")
        shown_filtered = sum(1 for row in rows.values() if row["state"] == "filtered")

        for port, row in rows.items():
            self._st[port] = row["state"]

        for port in open_ports:
            self._open_ports.append(port)
            live_ports.append(port)

        self._open = len(open_ports)
        shown_total = len(open_ports) + shown_closed + shown_filtered
        remaining = max(0, len(ports) - shown_total)
        self._filtered = shown_filtered + ignored["filtered"]
        self._closed = shown_closed + ignored["closed"]

        assigned = self._open + self._closed + self._filtered
        if assigned < len(ports):
            self._closed += len(ports) - assigned

        self._tested = len(ports)
        prog.update(tid, completed=len(ports))

        for port in open_ports:
            live.console.print(
                Text.assemble(
                    ("  ◉ ", GREEN),
                    (f"{port:>5}/tcp", f"bold {WHITE}"),
                    ("  →  ", DIM),
                    (guess_svc(port), SVC_COL),
                ),
            )

        await self._maybe_refresh_live(live, prog, live_ports, force=True)

        if self.cfg.svc_on and not self.cfg.aggr_on:
            for port in open_ports:
                await self._queue_service_detection(port)

        if rc != 0 and not open_ports:
            return err or "nmap discovery returned a non-zero exit code"

        if remaining and not rows and rc != 0:
            return err or "nmap discovery returned no parseable results"

        return None

    def _probe_fallback(
        self,
        port,
        t0,
        n_cmd,
        *,
        svc = None,
        info = "",
        err = None,
        raw = "",
    ):
        return SvcInfo(
            port=port,
            ok=True,
            state="open",
            svc=svc or guess_svc(port),
            info=info,
            elapsed=round(time.perf_counter() - t0, 3),
            n_cmd=n_cmd,
            raw=raw,
            err=err,
        )

    def _tls_info_from_writer(self, writer):
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return []
        try:
            cert = ssl_obj.getpeercert()
        except Exception:
            return []
        return _tls_cert_bits(cert)

    def _probe_timeout(self):
        # keep light probes from being stricter than the user-visible scan timeout.
        return max(HTTP_PROBE_TIMEOUT, self.cfg.c_to)

    async def _ssh_probe(self, ip, port):
        t0 = time.perf_counter()
        reader = None
        writer = None
        n_cmd = "light ssh probe"
        probe_timeout = self._probe_timeout()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=probe_timeout,
            )
            banner = await asyncio.wait_for(
                reader.read(SSH_BANNER_LIMIT),
                timeout=probe_timeout,
            )
            text = banner.decode(errors="ignore").strip()
            if not text:
                return self._probe_fallback(
                    port,
                    t0,
                    n_cmd,
                    svc="ssh",
                    info="no SSH banner",
                    err="probe-no-banner",
                )

            return SvcInfo(
                port=port,
                ok=True,
                state="open",
                svc="ssh",
                info=f"Banner: {_clean_text(text, 140)}",
                elapsed=round(time.perf_counter() - t0, 3),
                n_cmd=n_cmd,
                raw=text[:500],
                err=None,
            )
        except asyncio.TimeoutError:
            return self._probe_fallback(
                port,
                t0,
                n_cmd,
                svc="ssh",
                info="no SSH banner before probe timeout",
                err="probe-timeout",
            )
        except (ConnectionResetError, BrokenPipeError, OSError) as err:
            return self._probe_fallback(
                port,
                t0,
                n_cmd,
                svc="ssh",
                info="no SSH banner",
                err=str(err),
            )
        finally:
            if writer is not None:
                writer.close()
                if hasattr(writer, "wait_closed"):
                    try:
                        await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
                    except Exception:
                        pass

    async def _http_probe(self, ip, port):
        t0 = time.perf_counter()
        if self.cfg.stealth or self._http_probe_blocked:
            return SvcInfo(
                port=port,
                ok=True,
                state="open",
                svc=guess_svc(port),
                info="",
                elapsed=round(time.perf_counter() - t0, 3),
                n_cmd="",
                raw="",
                err=None,
            )

        guessed_ssl = port in TLS_WEB_PORTS
        host_header = self.cfg.target if not self._target_is_ip else ip
        n_cmd = "light http probe"
        probe_timeout = self._probe_timeout()
        attempt_notes = []
        final_err = "probe-no-banner"

        for attempt_idx, is_ssl in enumerate((guessed_ssl, not guessed_ssl)):
            reader = None
            writer = None
            scheme = "https" if is_ssl else "http"
            try:
                kwargs = {}
                if is_ssl:
                    kwargs["ssl"] = HTTP_SSL_CTX
                    if not self._target_is_ip:
                        kwargs["server_hostname"] = self.cfg.target

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, **kwargs),
                    timeout=probe_timeout,
                )
                tls_bits = self._tls_info_from_writer(writer) if is_ssl else []
                raw = await http_get_response(reader, writer, host_header, probe_timeout)
                if not raw:
                    detail_parts = list(tls_bits)
                    detail_parts.append("accepted TCP but returned no HTTP bytes")
                    attempt_notes.append(
                        f"{scheme.upper()}: {' | '.join(detail_parts)}"
                    )
                    continue

                svc_name, info, status_code = parse_http_banner(raw, port)
                if is_ssl:
                    svc_name = "https" if svc_name == "http" else svc_name
                info_parts = list(tls_bits)
                if info:
                    info_parts.append(info)

                if status_code in HTTP_BLOCK_STATUSES:
                    self._http_probe_blocked = True
                    info_parts.append("probe backoff enabled")

                if attempt_idx > 0:
                    info_parts.append(f"Probe: {scheme.upper()} fallback")

                return SvcInfo(
                    port=port,
                    ok=True,
                    state="open",
                    svc=svc_name,
                    info=" | ".join(info_parts),
                    elapsed=round(time.perf_counter() - t0, 3),
                    n_cmd=n_cmd,
                    raw=raw.decode(errors="ignore")[:800],
                    err=None,
                )
            except asyncio.TimeoutError:
                final_err = "probe-timeout"
                attempt_notes.append(f"{scheme.upper()}: probe timeout")
            except (
                ConnectionResetError,
                BrokenPipeError,
                OSError,
                ssl.SSLError,
            ) as err:
                final_err = "probe-no-banner"
                err_text = str(err).strip() or "connection closed before HTTP response"
                attempt_notes.append(f"{scheme.upper()}: {err_text[:120]}")
            except Exception as err:
                return SvcInfo(
                    port=port,
                    ok=True,
                    state="open",
                    svc=guess_svc(port),
                    info=f"light probe failed: {str(err)[:60]}",
                    elapsed=round(time.perf_counter() - t0, 3),
                    n_cmd=n_cmd,
                    raw="",
                    err=str(err),
                )
            finally:
                if writer is not None:
                    writer.close()
                    if hasattr(writer, "wait_closed"):
                        try:
                            await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
                        except Exception:
                            pass

        info_parts = ["no HTTP banner"]
        if len(attempt_notes) > 1:
            info_parts.append("tried HTTPS and HTTP")
        info_parts.extend(attempt_notes)
        if attempt_notes:
            info_parts.append(
                "service may require the other transport or a non-HTTP handshake"
            )

        return self._probe_fallback(
            port,
            t0,
            n_cmd,
            svc="https" if guessed_ssl else "http",
            info=" | ".join(info_parts),
            err=final_err,
        )

    async def _basic(self, ip, port):
        t0 = time.perf_counter()
        guessed_svc, guess_source = guess_svc_meta(port)

        if port in SSH_PROBE_PORTS or guessed_svc == "ssh":
            return await self._ssh_probe(ip, port)

        if should_try_http_probe(port, guessed_svc, guess_source):
            probe_res = await self._http_probe(ip, port)
            # the port is confirmed open, so a no-signal result is usually a
            # transient reset/rate-limit (common right after a large connect
            # discovery storm). measured recovery is ~1s, so retry past that
            # before giving up to a /etc/services guess.
            if not has_http_probe_signal(probe_res):
                for delay in (0.8, 1.5):
                    await asyncio.sleep(delay)
                    retry_res = await self._http_probe(ip, port)
                    if has_http_probe_signal(retry_res):
                        probe_res = retry_res
                        break
            if has_http_probe_signal(probe_res):
                return probe_res

            svc_name = guessed_svc
            if guess_source == "none" or (guess_source == "system" and port >= 1024):
                svc_name = "unknown"
            info_parts = []
            if guess_source == "system":
                info_parts.append(f"unverified system service guess: {guessed_svc}")
            elif guess_source == "builtin":
                info_parts.append(
                    f"probe inconclusive; using default service guess: {guessed_svc}"
                )
            elif probe_res.info:
                info_parts.append("service unresolved after HTTP probe")

            if probe_res.info:
                info_parts.append(probe_res.info)

            return SvcInfo(
                port=port,
                ok=True,
                state="open",
                svc=svc_name,
                info=" | ".join(info_parts),
                elapsed=probe_res.elapsed,
                n_cmd=probe_res.n_cmd,
                raw=probe_res.raw,
                err=probe_res.err,
            )

        return SvcInfo(
            port=port,
            ok=True,
            state="open",
            svc=guessed_svc,
            info="",
            elapsed=round(time.perf_counter() - t0, 3),
            n_cmd="",
            raw="",
            err=None,
        )

    async def _resolve(self, host):
        # skip getaddrinfo for bare IPs
        try:
            ip = ipaddress.ip_address(host)
            family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
            self._resolved_candidates = [host]
            return host, family
        except ValueError:
            pass

        loop = asyncio.get_running_loop()
        last_err = None

        for _ in range(2):
            try:
                infos = await loop.getaddrinfo(
                    host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
                )
                seen = set()
                v4 = []
                v6 = []

                for family, _socktype, _proto, _canon, sockaddr in infos:
                    if family not in {socket.AF_INET, socket.AF_INET6}:
                        continue

                    addr = sockaddr[0]
                    if addr in seen:
                        continue

                    seen.add(addr)
                    if family == socket.AF_INET:
                        v4.append(addr)
                    else:
                        v6.append(addr)

                ordered = v4 + v6
                if ordered:
                    self._resolved_candidates = ordered
                    if v4:
                        return v4[0], socket.AF_INET
                    return v6[0], socket.AF_INET6
                raise RuntimeError(f"no supported address family for {host}")
            except Exception as err:
                last_err = err
                await asyncio.sleep(0.1)

        raise RuntimeError(f"DNS resolution failed for {host}: {last_err}")

    async def _scan_epoll(
        self,
        ip,
        family,
        ports,
        prog,
        tid,
        live,
        live_ports,
    ):
        epoll = select.epoll()
        sockets = {}
        pending = deque(ports)
        retries = {}
        profile = self._scan_profile()
        retry_budget = int(profile.get("retry_budget", 0))
        dyn_timeout = self.cfg.c_to
        srtt = 0.0
        rttvar = 0.0
        min_timeout = float(profile.get("timeout_floor", 0.10))
        window_size = profile["window"]
        scan_delay = 0.0

        try:
            while pending or sockets:
                while len(sockets) < window_size and pending:
                    port = pending.popleft()
                    try:
                        sock = socket.socket(family, socket.SOCK_STREAM)
                        sock.setblocking(False)
                    except OSError as err:
                        if err.errno in (23, 24):
                            window_size = max(profile["min_window"], len(sockets))
                            break
                        await self._finish_port(
                            port, "closed", prog, tid, live_ports, live
                        )
                        continue

                    try:
                        sock.connect(sock_addr(ip, port, family))
                    except BlockingIOError:
                        pass
                    except OSError:
                        sock.close()
                        await self._finish_port(
                            port, "closed", prog, tid, live_ports, live
                        )
                        continue

                    fd = sock.fileno()
                    try:
                        epoll.register(
                            fd, select.EPOLLOUT | select.EPOLLERR | select.EPOLLHUP
                        )
                        sockets[fd] = (sock, port, time.perf_counter())
                    except Exception:
                        sock.close()
                        await self._finish_port(
                            port, "closed", prog, tid, live_ports, live
                        )

                now = time.perf_counter()
                try:
                    events = epoll.poll(0.02)
                except Exception:
                    events = []

                requeued_timeout = False
                for fd, event in events:
                    entry = sockets.pop(fd, None)
                    if entry is None:
                        continue

                    sock, port, started_at = entry
                    try:
                        epoll.unregister(fd)
                    except Exception:
                        pass

                    err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                    sock.close()
                    rtt = max(now - started_at, 0.001)

                    if srtt == 0.0:
                        srtt = rtt
                        rttvar = rtt / 2.0
                    else:
                        rttvar = (3.0 / 4.0) * rttvar + (1.0 / 4.0) * abs(srtt - rtt)
                        srtt = (7.0 / 8.0) * srtt + (1.0 / 8.0) * rtt

                    dyn_timeout = max(
                        min_timeout, min(self.cfg.c_to, srtt + 4.0 * rttvar)
                    )
                    window_size = min(
                        profile["max_window"], window_size + profile["increase"]
                    )

                    state = "open" if err == 0 and event & select.EPOLLOUT else "closed"
                    await self._finish_port(
                        state=state,
                        port=port,
                        prog=prog,
                        tid=tid,
                        live_ports=live_ports,
                        live=live,
                    )

                now = time.perf_counter()
                expired = []
                for fd, (sock, port, started_at) in list(sockets.items()):
                    if now - started_at > dyn_timeout:
                        expired.append((fd, sock, port))

                expired_count = len(expired)
                for fd, sock, port in expired:
                    try:
                        epoll.unregister(fd)
                    except Exception:
                        pass
                    sock.close()
                    del sockets[fd]

                    retry_count = retries.get(port, 0)
                    if retry_count < profile["max_retries"] and retry_budget > 0:
                        requeued_timeout = True
                        retry_budget -= 1
                        retries[port] = retry_count + 1
                        self._st[port] = "retrying"
                        pending.appendleft(port)
                    else:
                        await self._finish_port(
                            port, "filtered", prog, tid, live_ports, live
                        )

                if expired_count:
                    timeout_ratio = expired_count / max(1, expired_count + len(events))
                    if expired_count >= 4 and (
                        timeout_ratio >= 0.20
                        or expired_count >= max(8, window_size // 8)
                    ):
                        window_size = max(profile["min_window"], window_size // 2)
                        dyn_timeout = min(self.cfg.c_to, max(dyn_timeout, min_timeout))
                        if self.cfg.stealth:
                            scan_delay = min(
                                0.08, 0.01 if scan_delay == 0.0 else scan_delay * 2
                            )
                elif requeued_timeout:
                    window_size = max(profile["min_window"], window_size // 2)
                    if self.cfg.stealth:
                        scan_delay = min(
                            0.08, 0.01 if scan_delay == 0.0 else scan_delay * 2
                        )
                elif scan_delay > 0.0:
                    scan_delay = max(0.0, scan_delay / 2.0)

                await self._maybe_refresh_live(live, prog, live_ports)

                if scan_delay > 0.0:
                    await asyncio.sleep(scan_delay)
                else:
                    await asyncio.sleep(0)
        finally:
            for sock, _port, _started_at in sockets.values():
                sock.close()
            epoll.close()
            await self._maybe_refresh_live(live, prog, live_ports, force=True)

    async def _probe_sock_connect(
        self,
        ip,
        family,
        port,
        timeout,
    ):
        loop = asyncio.get_running_loop()
        started_at = time.perf_counter()

        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setblocking(False)
        except OSError:
            return "closed", time.perf_counter() - started_at, True

        try:
            await asyncio.wait_for(
                loop.sock_connect(sock, sock_addr(ip, port, family)),
                timeout=timeout,
            )
            return "open", time.perf_counter() - started_at, True
        except asyncio.TimeoutError:
            return "timeout", time.perf_counter() - started_at, False
        except OSError:
            return "closed", time.perf_counter() - started_at, True
        finally:
            sock.close()

    async def _ensure_syn_receiver(self):
        if self._raw_sock is None:
            return

        async with self._syn_receiver_lock:
            task = self._syn_receiver_task
            if task is not None and task.done():
                self._syn_receiver_task = None
                self._syn_receiver_running = False

            if self._syn_receiver_task is None:
                self._syn_receiver_running = True
                self._syn_receiver_task = asyncio.create_task(self._syn_receiver())

    async def _stop_syn_receiver(self):
        async with self._syn_receiver_lock:
            task = self._syn_receiver_task
            self._syn_receiver_running = False

        if task is None:
            return

        try:
            await asyncio.wait_for(task, timeout=1.0)
        except asyncio.TimeoutError:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        except asyncio.CancelledError:
            pass
        finally:
            async with self._syn_receiver_lock:
                if self._syn_receiver_task is task:
                    self._syn_receiver_task = None

    async def _syn_receiver(self):
        raw_sock = self._raw_sock
        if raw_sock is None:
            self._syn_receiver_running = False
            return

        loop = asyncio.get_running_loop()

        try:
            while self._syn_receiver_running or self._syn_tracking:
                try:
                    data = await loop.sock_recv(raw_sock, 65535)
                except asyncio.CancelledError:
                    raise
                except (BlockingIOError, InterruptedError):
                    await asyncio.sleep(0)
                    continue
                except OSError:
                    if self._syn_receiver_running:
                        await asyncio.sleep(0.01)
                        continue
                    break

                if not data:
                    await asyncio.sleep(0)
                    continue

                response = parse_tcp_response(data)
                if not response:
                    continue

                resp_src_port, resp_dst_port, flags = response

                async with self._syn_tracking_lock:
                    tracking = self._syn_tracking.get(resp_dst_port)
                    if tracking is None:
                        continue

                    dst_port, event, result_holder, started_at = tracking
                    if resp_src_port != dst_port:
                        continue

                    if flags & 0x12 == 0x12:  # SYN-ACK
                        state = "open"
                    elif flags & 0x04:  # RST or RST-ACK
                        state = "closed"
                    else:
                        continue

                    self._syn_tracking.pop(resp_dst_port, None)

                result_holder["state"] = state
                result_holder["rtt"] = time.perf_counter() - started_at
                result_holder["responded"] = True
                event.set()

        finally:
            self._syn_receiver_running = False

    async def _probe_syn_scan(
        self,
        ip,
        family,
        port,
        timeout,
        raw_sock,
        src_ip,
    ):
        if family != socket.AF_INET:
            # fall back to connect scan for IPv6
            return await self._probe_sock_connect(ip, family, port, timeout)

        started_at = time.perf_counter()
        loop = asyncio.get_running_loop()

        await self._ensure_syn_receiver()

        event = asyncio.Event()
        result_holder = {"state": "filtered", "rtt": 0.0, "responded": False}

        async with self._syn_tracking_lock:
            src_port = random.randint(1024, 65535)
            while src_port in self._syn_tracking:
                src_port = random.randint(1024, 65535)
            self._syn_tracking[src_port] = (port, event, result_holder, started_at)

        try:
            syn_packet = build_syn_packet(src_ip, ip, src_port, port)
            try:
                await loop.run_in_executor(None, raw_sock.sendto, syn_packet, (ip, 0))
            except OSError:
                return "filtered", time.perf_counter() - started_at, False

            try:
                await asyncio.wait_for(event.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                pass

            state = result_holder["state"]
            rtt = (
                result_holder["rtt"]
                if result_holder["responded"]
                else (time.perf_counter() - started_at)
            )
            responded = result_holder["responded"]

            return state, rtt, responded

        finally:
            async with self._syn_tracking_lock:
                self._syn_tracking.pop(src_port, None)

    async def _scan_syn(
        self,
        ip,
        family,
        ports,
        prog,
        tid,
        live,
        live_ports,
    ):
        if family != socket.AF_INET or self._raw_sock is None or self._src_ip is None:
            await self._scan_asyncio(ip, family, ports, prog, tid, live, live_ports)
            return

        raw_sock = self._raw_sock
        pending = deque(ports)
        inflight = {}
        retries = {}
        profile = self._scan_profile()
        retry_budget = int(profile.get("retry_budget", 0))
        dyn_timeout = self.cfg.c_to
        srtt = 0.0
        rttvar = 0.0
        min_timeout = float(profile.get("timeout_floor", 0.10))
        window_size = profile["window"]
        scan_delay = 0.0
        next_src_port = random.randint(32768, 65535)

        def alloc_src_port():
            nonlocal next_src_port

            for _ in range(65535 - 1024):
                src_port = next_src_port
                next_src_port += 1
                if next_src_port > 65535:
                    next_src_port = 1024
                if src_port not in inflight:
                    return src_port

            raise RuntimeError("exhausted SYN source ports")

        def update_rtt(rtt):
            nonlocal srtt, rttvar, dyn_timeout, window_size, scan_delay

            if srtt == 0.0:
                srtt = rtt
                rttvar = rtt / 2.0
            else:
                rttvar = (3.0 / 4.0) * rttvar + (1.0 / 4.0) * abs(srtt - rtt)
                srtt = (7.0 / 8.0) * srtt + (1.0 / 8.0) * rtt

            dyn_timeout = max(min_timeout, min(self.cfg.c_to, srtt + 4.0 * rttvar))
            window_size = min(profile["max_window"], window_size + profile["increase"])
            if scan_delay > 0.0:
                scan_delay = max(0.0, scan_delay / 2.0)

        try:
            while pending or inflight:
                while len(inflight) < window_size and pending:
                    port = pending.popleft()
                    src_port = alloc_src_port()
                    syn_packet = build_syn_packet(self._src_ip, ip, src_port, port)

                    try:
                        raw_sock.sendto(syn_packet, (ip, 0))
                    except (BlockingIOError, InterruptedError):
                        pending.appendleft(port)
                        break
                    except OSError:
                        self._finish_port_sync(port, "filtered", live_ports)
                        continue

                    inflight[src_port] = (port, time.perf_counter())

                got_response = False
                while True:
                    try:
                        data = raw_sock.recv(65535)
                    except (BlockingIOError, InterruptedError):
                        break
                    except OSError:
                        break

                    response = parse_tcp_response(data)
                    if not response:
                        continue

                    resp_src_port, resp_dst_port, flags = response
                    entry = inflight.get(resp_dst_port)
                    if entry is None:
                        continue

                    port, started_at = entry
                    if resp_src_port != port:
                        continue

                    if flags & 0x12 == 0x12:
                        state = "open"
                    elif flags & 0x04:
                        state = "closed"
                    else:
                        continue

                    inflight.pop(resp_dst_port, None)
                    rtt = max(time.perf_counter() - started_at, 0.001)
                    update_rtt(rtt)
                    self._finish_port_sync(port, state, live_ports)
                    got_response = True

                now = time.perf_counter()
                expired = []
                for src_port, (port, started_at) in list(inflight.items()):
                    if now - started_at > dyn_timeout:
                        expired.append((src_port, port))

                expired_count = len(expired)
                requeued_timeout = False
                for src_port, port in expired:
                    inflight.pop(src_port, None)

                    retry_count = retries.get(port, 0)
                    if retry_count < profile["max_retries"] and retry_budget > 0:
                        requeued_timeout = True
                        retry_budget -= 1
                        retries[port] = retry_count + 1
                        self._st[port] = "retrying"
                        pending.appendleft(port)
                    else:
                        self._finish_port_sync(port, "filtered", live_ports)

                if expired_count:
                    timeout_ratio = expired_count / max(
                        1, expired_count + (1 if got_response else 0)
                    )
                    if expired_count >= 4 and (
                        timeout_ratio >= 0.20
                        or expired_count >= max(8, window_size // 8)
                    ):
                        window_size = max(profile["min_window"], window_size // 2)
                        dyn_timeout = min(self.cfg.c_to, max(dyn_timeout, min_timeout))
                        if self.cfg.stealth:
                            scan_delay = min(
                                0.08, 0.01 if scan_delay == 0.0 else scan_delay * 2
                            )
                elif requeued_timeout:
                    window_size = max(profile["min_window"], window_size // 2)
                    if self.cfg.stealth:
                        scan_delay = min(
                            0.08, 0.01 if scan_delay == 0.0 else scan_delay * 2
                        )
                elif scan_delay > 0.0:
                    scan_delay = max(0.0, scan_delay / 2.0)

                prog.update(tid, completed=self._tested)
                await self._maybe_refresh_live(live, prog, live_ports)

                if pending or inflight:
                    if scan_delay > 0.0:
                        await asyncio.sleep(scan_delay)
                    elif inflight and not pending:
                        now = time.perf_counter()
                        earliest = min(st for _, st in inflight.values())
                        remaining = (earliest + dyn_timeout) - now
                        if remaining > 0.003:
                            loop = asyncio.get_running_loop()
                            fut = loop.create_future()
                            fd = raw_sock.fileno()
                            def _on_readable(f = fut):
                                if not f.done():
                                    f.set_result(None)
                            loop.add_reader(fd, _on_readable)
                            try:
                                await asyncio.wait_for(fut, timeout=remaining)
                            except asyncio.TimeoutError:
                                pass
                            finally:
                                loop.remove_reader(fd)
                            continue
                        else:
                            await asyncio.sleep(0)
                    elif got_response:
                        await asyncio.sleep(0)
                    else:
                        await asyncio.sleep(0.001)
        finally:
            prog.update(tid, completed=self._tested)
            await self._maybe_refresh_live(live, prog, live_ports, force=True)

    async def _scan_asyncio(
        self,
        ip,
        family,
        ports,
        prog,
        tid,
        live,
        live_ports,
    ):
        profile = self._scan_profile()
        dyn_timeout = self.cfg.c_to
        srtt = 0.0
        rttvar = 0.0
        min_timeout = float(profile.get("timeout_floor", 0.10))
        retry_budget = int(profile.get("retry_budget", 0))
        dyn_sem = DynamicSemaphore(profile["window"])
        dyn_sem.max_value = profile["max_window"]
        scan_delay = 0.0

        async def scan_port(port):
            nonlocal dyn_timeout, srtt, rttvar, scan_delay, retry_budget
            retries = 0

            while True:
                await dyn_sem.acquire()
                try:
                    if self.cfg.syn_scan and self._raw_sock and self._src_ip:
                        state, rtt, responded = await self._probe_syn_scan(
                            ip, family, port, dyn_timeout, self._raw_sock, self._src_ip
                        )
                    else:
                        state, rtt, responded = await self._probe_sock_connect(
                            ip, family, port, dyn_timeout
                        )
                finally:
                    await dyn_sem.release()

                if responded:
                    async with self._lock:
                        if srtt == 0.0:
                            srtt = rtt
                            rttvar = rtt / 2.0
                        else:
                            rttvar = (3.0 / 4.0) * rttvar + (1.0 / 4.0) * abs(
                                srtt - rtt
                            )
                            srtt = (7.0 / 8.0) * srtt + (1.0 / 8.0) * rtt
                        dyn_timeout = max(
                            min_timeout, min(self.cfg.c_to, srtt + 4.0 * rttvar)
                        )
                    await dyn_sem.set_value(
                        min(profile["max_window"], dyn_sem.value + profile["increase"])
                    )
                    if scan_delay > 0.0:
                        scan_delay = max(0.0, scan_delay / 2.0)
                    await self._finish_port(port, state, prog, tid, live_ports, live)
                    break

                retries += 1
                should_retry = retries <= profile["max_retries"] and retry_budget > 0
                if not should_retry:
                    await dyn_sem.set_value(
                        max(profile["min_window"], dyn_sem.value // 2)
                    )
                    await self._finish_port(
                        port, "filtered", prog, tid, live_ports, live
                    )
                    break

                retry_budget -= 1
                await dyn_sem.set_value(max(profile["min_window"], dyn_sem.value // 2))
                self._st[port] = "retrying"
                if self.cfg.stealth:
                    scan_delay = min(
                        0.08, 0.01 if scan_delay == 0.0 else scan_delay * 2
                    )
                    await asyncio.sleep(scan_delay)

                await self._maybe_refresh_live(live, prog, live_ports)

        await asyncio.gather(*[asyncio.create_task(scan_port(port)) for port in ports])
        await self._maybe_refresh_live(live, prog, live_ports, force=True)

    async def _run_service_detection(self, ip):
        if not self._open_ports:
            return

        if not self.cfg.svc_on:
            self._svcs = [
                SvcInfo(
                    port=port,
                    ok=True,
                    state="open",
                    svc=guess_svc(port),
                    info="",
                    elapsed=0.0,
                    n_cmd="",
                    raw="",
                    err=None,
                )
                for port in self._open_ports
            ]
            return

        if self.cfg.aggr_on:
            await self._queue_service_detection_batch(ip, self._open_ports)
        else:
            for port in self._open_ports:
                await self._queue_service_detection(port)

        waiters = list(self._svc_tasks)

        if waiters:
            show_progress = any(
                not waiter.done() for waiter in waiters
            ) or self._svc_done < len(self._open_ports)
            waiter = asyncio.gather(*waiters)

            if show_progress and not self.cfg.quiet:
                console.print()
                svc_prog = mk_prog(transient=True)
                with svc_prog:
                    t2 = svc_prog.add_task(
                        "Service detection",
                        total=len(self._open_ports),
                        completed=min(self._svc_done, len(self._open_ports)),
                    )
                    while not waiter.done():
                        svc_prog.update(
                            t2,
                            completed=min(self._svc_done, len(self._open_ports)),
                        )
                        await asyncio.sleep(SVC_PROGRESS_POLL)
                    await waiter
                    svc_prog.update(t2, completed=len(self._open_ports))
            else:
                await waiter

        self._svcs = []
        for port in sorted(self._open_ports):
            self._svcs.append(
                self._svc_results.get(
                    port,
                    SvcInfo(
                        port=port,
                        ok=True,
                        state="open",
                        svc=guess_svc(port),
                        info="",
                        elapsed=0.0,
                        n_cmd="",
                        raw="",
                        err=None,
                    ),
                )
            )

    async def run(self):
        started = datetime.now(timezone.utc)
        t0 = time.perf_counter()
        ip, family = await self._resolve(self.cfg.target)
        self._resolved_ip = ip
        self._ensure_syn_socket(ip)
        use_syn_scan = (
            self.cfg.syn_scan
            and family == socket.AF_INET
            and self._raw_sock is not None
            and self._src_ip is not None
        )
        ports = self._ordered_ports()
        errors = []

        if len(self._resolved_candidates) > 1:
            errors.append(
                f"hostname resolved to {len(self._resolved_candidates)} addresses; scanning {ip}"
            )
            if not self.cfg.quiet:
                console.print(
                    Text(
                        f"  note  {self.cfg.target} resolved to {len(self._resolved_candidates)} addresses; scanning {ip}",
                        style=DIM,
                    )
                )

        live_ports = []

        # no-op stubs for quiet mode
        if self.cfg.quiet:
            _null_console = Console(
                file=io.StringIO(),
                highlight=False,
                force_terminal=False,
                color_system=None,
            )
            prog = type("_P", (), {
                "add_task": lambda self, *a, **kw: 0,
                "advance": lambda self, tid: None,
                "update": lambda self, tid, **kw: None,
            })()
            tid = prog.add_task("", total=len(ports))
            live = type("_L", (), {
                "console": _null_console,
                "start": lambda self: None,
                "stop": lambda self: None,
                "update": lambda self, *a, **kw: None,
            })()
        else:
            prog = mk_prog(transient=False)
            tid = prog.add_task(f"Scanning {self.cfg.target}", total=len(ports))
            live = Live(
                build_live_panel(prog, live_ports, self.cfg.target),
                console=console,
                refresh_per_second=8,
                transient=True,
            )
            live.start()

        try:
            if self.cfg.sudo_pw is not None:
                err = await self._nmap_discover(
                    self.cfg.target, ports, prog, tid, live, live_ports
                )
                if err:
                    errors.append(f"hybrid discovery fallback: {err}")
                    self._reset_scan_state()
                    live_ports.clear()
                    prog.update(tid, completed=0)
                    await self._maybe_refresh_live(live, prog, live_ports, force=True)
                    if use_syn_scan:
                        await self._scan_syn(
                            ip, family, ports, prog, tid, live, live_ports
                        )
                    elif hasattr(select, "epoll") and not self.cfg.quiet:
                        await self._scan_epoll(
                            ip, family, ports, prog, tid, live, live_ports
                        )
                    else:
                        await self._scan_asyncio(
                            ip, family, ports, prog, tid, live, live_ports
                        )
            elif use_syn_scan:
                await self._scan_syn(ip, family, ports, prog, tid, live, live_ports)
            elif hasattr(select, "epoll") and not self.cfg.quiet:
                await self._scan_epoll(ip, family, ports, prog, tid, live, live_ports)
            else:
                await self._scan_asyncio(ip, family, ports, prog, tid, live, live_ports)
        finally:
            if not self.cfg.quiet:
                live.stop()
            await self._stop_syn_receiver()
            if self._raw_sock is not None:
                self._raw_sock.close()
                self._raw_sock = None

        self._open_ports.sort()
        await self._run_service_detection(ip)
        self._svcs.sort(key=lambda x: x.port)

        result = ScanOut(
            target=self.cfg.target,
            ip=ip,
            req_ports=self.cfg.ports,
            open_ports=self._open_ports,
            svcs=self._svcs,
            started=started.isoformat(),
            finished=datetime.now(timezone.utc).isoformat(),
            elapsed=round(time.perf_counter() - t0, 3),
            errors=errors,
        )
        result._filtered_count = self._filtered
        result._closed_count = self._closed
        return result


async def scan_quiet(
    target,
    ports,
    *,
    rip = None,
    concurrency = 256,
    timeout = 1.0,
    stealth = False,
):
    """
    quiet scanner hook for other modules.
    reuses a pre-resolved ip when available and suppresses live ui output.
    """

    cfg = Cfg(
        target=target,
        ports=list(ports),
        c_conc=max(1, min(concurrency, max(1, len(ports)))),
        c_to=timeout,
        s_conc=1,
        n_args=[],
        svc_on=False,
        aggr_on=False,
        sudo_pw=None,
        stealth=stealth,
        syn_scan=False,
        verbose=0,
        quiet=True,
    )

    scanner = Scanner(cfg)
    orig_resolve = scanner._resolve
    orig_console = console

    if rip:
        try:
            family = (
                socket.AF_INET6
                if ipaddress.ip_address(rip).version == 6
                else socket.AF_INET
            )

            async def _resolve_override(_host):
                return rip, family

            scanner._resolve = _resolve_override
        except ValueError:
            pass

    try:
        globals()["console"] = Console(
            file=io.StringIO(),
            highlight=False,
            force_terminal=False,
            color_system=None,
        )
        return await scanner.run()
    finally:
        scanner._resolve = orig_resolve
        globals()["console"] = orig_console



# main entry point
def run_cli(argv = None, prog = None):
    os.environ["PYTHONUNBUFFERED"] = "1"
    parser = build_parser(prog=prog)
    args = parser.parse_args(argv)

    targets = [t.strip() for t in args.target if t.strip()]
    if args.input_file:
        try:
            with open(args.input_file) as f:
                for line in f:
                    t = line.strip()
                    if t and not t.startswith("#"):
                        targets.append(t)
        except OSError as err:
            console.print(Text(f"  ERROR  Cannot read {args.input_file}: {err}", style=RED))
            return 2
    if not targets:
        console.print(Text("  ERROR  No target specified.", style=RED))
        return 2
    if args.quiet and args.v:
        console.print(Text("  ERROR  Choose either -v or -q, not both.", style=RED))
        return 2

    # validate
    if args.concurrency < 1 or args.svc_concurrency < 1:
        console.print(Text("  ERROR  Concurrency values must be >= 1.", style=RED))
        return 2
    if args.timeout <= 0:
        console.print(Text("  ERROR  Timeout must be > 0.", style=RED))
        return 2
    if (args.aggr_svc_scan or args.sudo_nmap) and shutil.which("nmap") is None:
        console.print(Text("  ERROR  nmap binary not found in PATH.", style=RED))
        return 2

    # determine scan mode
    use_syn_scan = args.syn_scan

    # SYN scan needs raw sockets, which require root. if we're not privileged,
    # transparently re-run ourselves under sudo. root is held only for the
    # child's lifetime and released automatically on exit, so nothing persists.
    # (skip when using agents: the local process opens no raw sockets then,
    # each agent handles its own privilege via the nsenter sudo prompt.)
    # maybe a bad design choice, but it's very convinient.
    if use_syn_scan and args.agents <= 0 and os.geteuid() != 0:
        can_syn = False
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            probe.close()
            can_syn = True
        except (PermissionError, OSError):
            pass

        if not can_syn:
            exe = shutil.which(sys.argv[0]) or os.path.abspath(sys.argv[0])
            # run the elevated child with bytecode writes disabled. otherwise
            # root creates root-owned __pycache__/*.pyc inside a user-owned
            # (pipx) install, which then breaks `pipx` ops run as the normal
            # user with PermissionError. `env VAR=val` survives sudo's env reset.
            sudo_cmd = ["sudo", "env", "PYTHONDONTWRITEBYTECODE=1", exe] + sys.argv[1:]
            console.print()
            console.print(Text("  SYN scan requires root, elevating with sudo...", style=YELLOW))
            console.print()
            try:
                proc = subprocess.run(sudo_cmd)
            except KeyboardInterrupt:
                return 130
            except FileNotFoundError:
                console.print(Text("  ERROR  sudo not found; run as root.", style=f"bold {RED}"))
                return 2
            return proc.returncode

    # sudo handling
    sudo_pw = None
    if args.sudo_nmap:
        sudo_pw = getpass.getpass("  sudo password: ")
        check = subprocess.run(
            ["sudo", "-S", "-p", "", "-v"],
            input=sudo_pw + "\n",
            text=True,
            capture_output=True,
        )
        if check.returncode != 0:
            console.print(Text("  ERROR  sudo authentication failed.", style=RED))
            return 2

    if args.agents > 0 and not os.environ.get("SUDO_PASSWORD"):
        console.print()
        console.print(Text("  Agent scan needs sudo for nsenter.", style=YELLOW))
        try:
            agent_pw = getpass.getpass("  sudo password: ")
        except (EOFError, KeyboardInterrupt):
            agent_pw = ""
        if not agent_pw:
            console.print(Text("  ERROR  sudo password required for agent scan", style=RED))
            return 2
        check = subprocess.run(
            ["sudo", "-S", "-p", "", "-v"],
            input=agent_pw + "\n",
            text=True,
            capture_output=True,
        )
        if check.returncode != 0:
            console.print(Text("  ERROR  sudo authentication failed.", style=RED))
            return 2
        os.environ["SUDO_PASSWORD"] = agent_pw

    # determine ports to scan
    if args.all_ports:
        sel = list(range(1, 65536))
    elif args.ports:
        sel = parse_ports(args.ports)
    else:
        sel = top_ports(args.top_ports)

    if not sel:
        console.print(Text("  ERROR  No valid ports selected.", style=RED))
        return 2

    use_nmap_service_detection = args.aggr_svc_scan or args.sudo_nmap
    parsed_n_args = shlex.split(args.nmap_args)

    # show header
    scan_cfg = Cfg(
        target="",
        ports=sel,
        c_conc=args.concurrency,
        c_to=args.timeout,
        s_conc=args.svc_concurrency,
        n_args=parsed_n_args,
        svc_on=not args.no_svc_scan,
        aggr_on=use_nmap_service_detection,
        sudo_pw=sudo_pw,
        stealth=args.stealth,
        syn_scan=use_syn_scan,
        verbose=args.v,
        quiet=args.quiet,
        max_retries=args.retries,
    )
    if not args.quiet:
        display = [args.input_file] if args.input_file else targets
        hdr(display, len(sel), scan_cfg)

    runs = []
    # a single host uses the per-host Scanner (rich live panel, adaptive
    # RTT-paced engine with per-port retransmit, accurate closed/filtered
    # accounting) for BOTH connect and SYN. the bulk engine is for many hosts
    # or when agents fan the work out (-A).
    use_scanner = len(targets) == 1 and args.agents <= 0

    if use_scanner:
        cfg = Cfg(
            target=targets[0],
            ports=list(sel),
            c_conc=args.concurrency,
            c_to=args.timeout,
            s_conc=args.svc_concurrency,
            n_args=parsed_n_args,
            svc_on=not args.no_svc_scan,
            aggr_on=use_nmap_service_detection,
            sudo_pw=sudo_pw,
            stealth=args.stealth,
            syn_scan=use_syn_scan,
            verbose=args.v,
            quiet=args.quiet,
            max_retries=args.retries,
        )
        try:
            runs.append(asyncio.run(Scanner(cfg).run()))
        except Exception as err:
            t = Text()
            t.append("  ERROR  ", style=f"bold {RED}")
            t.append(f"{targets[0]}: {err}", style=DIM)
            console.print(t)
            return 1
    else:
        if args.agents > 0:
            raw = scan_with_agents(
                targets=targets, ports=sel, timeout=args.timeout,
                agent_count=args.agents, quiet=args.quiet,
                no_svc=args.no_svc_scan,
                retries=args.retries,
                batch=args.batch,
                batch_delay_ms=args.batch_delay,
            )
        else:
            raw = asyncio.run(
                scan_targets_parallel(
                    targets=targets,
                    ports=sel,
                    c_conc=args.concurrency,
                    c_to=args.timeout,
                    s_conc=args.svc_concurrency,
                    n_args=parsed_n_args,
                    svc_on=not args.no_svc_scan,
                    aggr_on=use_nmap_service_detection,
                    sudo_pw=sudo_pw,
                    stealth=args.stealth,
                    syn_scan=use_syn_scan,
                    verbose=args.v,
                    target_concurrency=args.target_concurrency,
                    quiet=args.quiet,
                    retries=args.retries,
                    batch=args.batch,
                    batch_delay_ms=args.batch_delay,
                )
            )
        for i, result in enumerate(raw):
            if isinstance(result, Exception):
                t = Text()
                t.append("  ERROR  ", style=f"bold {RED}")
                t.append(f"{targets[i]}: {result}", style=DIM)
                console.print(t)
                continue
            if isinstance(result, ScanHit):
                runs.append(result)
            elif isinstance(result, dict) and "target" in result:
                svc_list = []
                for s in result.get("services", []):
                    svc_list.append(SvcInfo(
                        port=s.get("port", 0),
                        ok=s.get("ok", True),
                        state=s.get("state", "open"),
                        svc=s.get("service", s.get("svc", "unknown")),
                        info=s.get("info", ""),
                        elapsed=s.get("elapsed_sec", s.get("elapsed", 0)),
                        n_cmd=s.get("nmap_cmd", s.get("n_cmd", "")),
                        raw=s.get("raw", ""),
                        err=s.get("err"),
                    ))
                runs.append(ScanHit(
                    target=result["target"],
                    ip=result.get("ip", ""),
                    req_ports=result.get("req_ports", sel),
                    open_ports=result.get("open_ports", []),
                    svcs=svc_list,
                    started=result.get("started", ""),
                    finished=result.get("finished", ""),
                    elapsed=result.get("elapsed_sec", result.get("elapsed", 0)),
                    errors=result.get("errors", []),
                ))

    if len(targets) > 1:
        opened = [r for r in runs if r.open_ports]
        total_ports = sum(len(r.open_ports) for r in runs)
        console.print()
        console.print(Text(f"  {len(opened)}/{len(runs)} hosts open, {total_ports} ports total", style=f"bold {CYAN}"))
        console.print()
    elif runs:
        show_scan(runs[0], idx=0, total=1, verbose=args.v)

    # write json or html output
    if args.out and runs:
        out_path, mode = _out_mode(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        if mode == "json":
            payload = (
                [scan.to_dict() for scan in runs]
                if len(runs) > 1
                else runs[0].to_dict()
            )
            out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        elif mode == "csv":
            out_path.write_text(_scan_csv(runs), encoding="utf-8")
        else:
            out_path.write_text(build_scan_html(runs), encoding="utf-8")

        if args.v:
            console.print(Text(f"  output mode  {mode}  ->  {out_path}", style=DIMMER))
        t = Text()
        t.append("  Report saved  ", style=DIM)
        t.append(str(out_path), style=CYAN)
        console.print(t)
        console.print()

    return 0


def main():
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()


__all__ = [
    "Cfg",
    "ScanOut",
    "Scanner",
    "SvcInfo",
    "build_live_panel",
    "build_parser",
    "build_scan_html",
    "build_syn_packet",
    "run_cli",
    "scan_quiet",
]
