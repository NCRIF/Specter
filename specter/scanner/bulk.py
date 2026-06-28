# bulk / parallel / agent-based scanning.
#
# this is the multi-target + high-throughput engine, kept separate from the
# per-host Scanner (port_scan.py). it contains the AF_PACKET bulk SYN probe,
# the WARP-agent fan-out, the lightweight async service probe, and the
# many-targets-at-once orchestrator.

import asyncio
import ipaddress
import os
import random
import select
import socket
import time
from datetime import datetime, timezone

from rich.text import Text

from ..core.results import ScanHit
from ..libs.port.builders import console
from ..libs.port.constants import CYAN, DIM, DIMMER, GREEN, RED, SVC_COL, WHITE
from ..libs.port.firewall import fw_add, fw_cleanup
from ..libs.port.models import SvcInfo
from ..libs.port.packets import build_syn_with_ip, parse_tcp_response_full
from ..libs.port.parsers import guess_svc
from ..libs.port.probes import http_get_response, parse_http_banner


async def bulk_syn_probe(
    per_target,
    resolved,
    ports,
    timeout,
    retries = 0,
    batch = 20,
    batch_delay_ms = 4.0,
    on_open=None,
):
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    raw_sock.setblocking(False)

    # receive via AF_PACKET (link layer, below netfilter).
    # this lets us drop the kernel's view of replies in INPUT (no RST, no
    # conntrack) while still capturing every SYN-ACK ourselves.
    ETH_P_IP = 0x0800
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024 * 1024)
    try:
        recv_sock.setsockopt(socket.SOL_SOCKET, 33, 64 * 1024 * 1024)
    except OSError:
        pass
    recv_sock.setblocking(False)

    src_ip = "0.0.0.0"
    try:
        test = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for target, ip, family, _err in resolved:
            if ip and family == socket.AF_INET:
                test.connect((ip, 80))
                src_ip = test.getsockname()[0]
                break
        test.close()
    except Exception:
        pass

    # single fixed source port for the whole scan lets the INPUT-DROP rule be
    # precise (only our scan's replies), and replies are matched by responder
    # ip:port so we never depend on a per-probe source port.
    scan_sport = random.randint(40000, 60000)
    fw_active = fw_add(scan_sport) # fw = 'fuck with' btw :p

    PACKET_OUTGOING = 4
    # map responder identity (target_ip, target_port) -> our target key.
    ip_target = {}
    port_set = set(ports)
    for target, ip, family, _err in resolved:
        if ip and family == socket.AF_INET:
            ip_target[ip] = target

    def _drain():
        while True:
            try:
                data, addr = recv_sock.recvfrom(65535)
            except (BlockingIOError, OSError):
                break
            # addr[2] is the packet type, skip our own outgoing copies
            if len(addr) > 2 and addr[2] == PACKET_OUTGOING:
                continue
            resp = parse_tcp_response_full(data)
            if not resp:
                continue
            resp_ip, resp_sport, resp_dport, flags = resp
            # only consider replies addressed to our scan source port
            if resp_dport != scan_sport:
                continue
            # the reply's source ip:port IS the scanned target ip:port
            target = ip_target.get(resp_ip)
            if target is None or resp_sport not in port_set:
                continue
            port = resp_sport
            probes = per_target[target]["probes"]
            if port in probes:
                continue
            if flags & 0x12 == 0x12:
                per_target[target]["open"].append(port)
                probes[port] = ("open", 0.0)
                if on_open is not None:
                    on_open(target, resp_ip, port)
            elif flags & 0x04:
                probes[port] = ("closed", 0.0)

    pairs = [
        (target, ip, port)
        for target, ip, family, _err in resolved
        if ip and family == socket.AF_INET
        for port in ports
    ]

    try:
        rounds = max(1, retries + 1)
        for rnd in range(rounds):
            pending = [
                (target, ip, port)
                for target, ip, port in pairs
                if port not in per_target[target]["probes"]
            ]
            if not pending:
                break
            sent = 0
            for target, ip, port in pending:
                pkt = build_syn_with_ip(src_ip, ip, scan_sport, port)
                try:
                    raw_sock.sendto(pkt, (ip, 0))
                except OSError:
                    continue
                sent += 1
                if batch > 0 and sent % batch == 0:
                    time.sleep(batch_delay_ms / 1000.0)
                    _drain()

            deadline = time.perf_counter() + timeout
            ep = select.epoll()
            ep.register(recv_sock.fileno(), select.EPOLLIN)
            _drain()
            while time.perf_counter() < deadline:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    break
                try:
                    events = ep.poll(remaining)
                except Exception:
                    break
                for fd, ev in events:
                    if ev & select.EPOLLIN:
                        _drain()
            ep.close()
    finally:
        raw_sock.close()
        recv_sock.close()
        if fw_active:
            fw_cleanup()


def print_compact_host(result):
    ports = result.get("open_ports", [])
    if not ports:
        return
    ports_str = ",".join(str(p) for p in ports)
    line = f"  {result['target']}  →  [{ports_str}]"
    print(line, flush=True)
    for s in result.get("services", []):
        svc_name = s.get("service", s.get("svc", "unknown"))
        banner = s.get("info", "")[:80]
        print(f"    :{s.get('port',0):<6} {svc_name:<14} {banner}", flush=True)


def scan_with_agents(targets, ports, timeout, agent_count, quiet, no_svc=False,
                     retries=1, overlap=False, batch=20, batch_delay_ms=4.0):
    from ..libs.agents import setup_agent_image, agents_spawn, agent_scan

    # agents only DISCOVER ports (always -N). doing the HTTP banner grab inside
    # each agent would route it through that container's WARP tunnel (an extra,
    # flaky hop) and fail intermittently. service detection is done once,
    # host-side, on the merged open ports below.
    extra = ["-N"]

    if not os.environ.get("SUDO_PASSWORD"):
        console.print(Text("ERROR sudo password required for agent scan", style=RED))
        return []

    if not quiet:
        console.print(Text(f"  Agents  {agent_count}  |  setting up", style=DIM))

    if not setup_agent_image():
        return []

    agents = agents_spawn(agent_count)
    if not agents:
        return []

    n = len(agents)
    if os.environ.get("X3R0_AGENT_OVERLAP", "0") == "1":
        overlap = True
    elif os.environ.get("X3R0_AGENT_OVERLAP") == "0":
        overlap = False

    # build per-agent work units: (target_chunk, ports_for_that_agent)
    split_ports = len(targets) == 1 and len(ports) >= n
    if split_ports:
        # one host, many ports: split the PORT RANGE across agents so a single
        # huge scan runs in parallel through n different WARP exit IPs.
        work = [(list(targets), ports[i::n]) for i in range(n)]
        work = [w for w in work if w[1]]
    elif overlap:
        # every agent scans the full target list from its own exit IP. the
        # union across vantage points maximizes host coverage.
        work = [(list(targets), list(ports)) for _ in range(n)]
    else:
        chunk_size = max(1, len(targets) // n)
        tchunks = [targets[i:i + chunk_size] for i in range(0, len(targets), chunk_size)]
        work = [(tc, list(ports)) for tc in tchunks[:n]]

    import tempfile, json, shutil
    from concurrent.futures import ThreadPoolExecutor, as_completed

    tmpdir = tempfile.mkdtemp(prefix="spec_agents_")

    def _run(agent_name, chunk, agent_ports, idx):
        out_file = os.path.join(tmpdir, f"{agent_name}_{idx}.json")
        ports_str = ",".join(str(p) for p in agent_ports)
        code, stdout, stderr = agent_scan(
            agent_name, chunk, ports_str, timeout, out_file, extra, retries,
            batch, batch_delay_ms,
        )
        if code == 0:
            try:
                with open(out_file) as f:
                    data = json.load(f)
                return data if isinstance(data, list) else [data]
            except Exception:
                pass
        return []

    if not quiet:
        if split_ports:
            desc = f"splitting {len(ports)} ports on {targets[0]} across {len(work)} agents"
        else:
            mode = "overlap" if overlap else "partition"
            desc = f"scanning {len(targets)} targets ({mode})"
        console.print(Text(f"  Agents  {len(work)}  |  {desc}, R={retries}", style=DIM))

    # union by target: a port is open if ANY vantage point saw SYN-ACK
    merged = {}

    def _merge(item):
        if not isinstance(item, dict) or "target" not in item:
            return
        tgt = item["target"]
        cur = merged.get(tgt)
        if cur is None:
            merged[tgt] = item
            return
        op = set(cur.get("open_ports") or []) | set(item.get("open_ports") or [])
        cur["open_ports"] = sorted(op)
        if not cur.get("services") and item.get("services"):
            cur["services"] = item["services"]
        if not cur.get("ip") and item.get("ip"):
            cur["ip"] = item["ip"]

    with ThreadPoolExecutor(max_workers=len(work)) as ex:
        futures = {
            ex.submit(_run, agents[i], work[i][0], work[i][1], i): i
            for i in range(len(work))
        }
        printed = set()
        for fut in as_completed(futures):
            try:
                r = fut.result()
            except Exception:
                continue
            items = r if isinstance(r, list) else ([r] if r else [])
            for item in items:
                _merge(item)
                # stream hosts the moment the agent that found them finishes
                if not quiet and isinstance(item, dict) and item.get("open_ports"):
                    tgt = item.get("target")
                    if tgt not in printed:
                        printed.add(tgt)
                        print_compact_host(merged.get(tgt, item))

    shutil.rmtree(tmpdir, ignore_errors=True)

    results = list(merged.values())
    for item in results:
        item["req_ports"] = list(ports)

    # service detection run once from the host on the merged open ports.
    # direct connection (not through an agent's WARP tunnel) so banners are
    # reliable, and it's only a handful of ports so no rate-limit concern so win-win.
    if not no_svc:
        async def _detect():
            sem = asyncio.Semaphore(20)
            tasks, meta = [], []
            for item in results:
                ip = item.get("ip") or item.get("target")
                if not ip:
                    continue
                for port in item.get("open_ports", []):
                    tasks.append(bulk_svc_probe(
                        item.get("target"), ip, port, sem, max(timeout, 2.0),
                        socket.AF_INET,
                    ))
                    meta.append(item)
            done = await asyncio.gather(*tasks, return_exceptions=True)
            for item, res in zip(meta, done):
                if not (isinstance(res, tuple) and len(res) == 3):
                    continue
                _t, _p, svc = res
                svc_list = item.setdefault("services", [])
                svc_list[:] = [s for s in svc_list if s.get("port") != svc.port]
                svc_list.append({
                    "port": svc.port, "ok": svc.ok, "state": svc.state,
                    "service": svc.svc, "info": svc.info,
                    "elapsed": svc.elapsed, "raw": svc.raw, "err": svc.err,
                })
        try:
            asyncio.run(_detect())
        except RuntimeError:
            pass

    if quiet:
        for item in results:
            if item.get("open_ports"):
                print_compact_host(item)
    return results


def show_compact(runs):
    opened = [r for r in runs if r.open_ports]
    if not opened:
        console.print(Text("  No open ports found.", style=DIM))
        return
    console.print()
    for r in opened:
        ports_str = ",".join(str(p) for p in r.open_ports)
        console.print(
            Text.assemble(
                ("  ", DIM),
                (r.target, f"bold {WHITE}"),
                ("  →  [", DIM),
                (ports_str, GREEN),
                ("]", DIM),
            )
        )
        if r.svcs:
            for svc in r.svcs:
                banner = svc.info[:80] if svc.info else ""
                console.print(
                    Text.assemble(
                        ("    ", DIM),
                        (f":{svc.port:<6}", CYAN),
                        (f"{svc.svc:<14}", SVC_COL if svc.svc != "unknown" else DIM),
                        (banner, DIMMER),
                    )
                )
    console.print()
    console.print(Text(f"  {len(opened)} hosts with open ports", style=DIM))
    console.print()


async def bulk_svc_probe(
    target, ip, port,
    sem, timeout, family,
):
    async with sem:
        t0 = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, family=family),
                timeout=timeout,
            )
            raw = await http_get_response(reader, writer, target, timeout)
            elapsed = round(time.perf_counter() - t0, 3)
            svc_name, info, _ = parse_http_banner(raw, port)
            return (target, port, SvcInfo(
                port=port, ok=True, state="open",
                svc=svc_name, info=info,
                elapsed=elapsed, n_cmd="light http probe",
                raw=(raw or b"").decode(errors="ignore")[:500], err=None,
            ))
        except Exception:
            elapsed = round(time.perf_counter() - t0, 3)
            return (target, port, SvcInfo(
                port=port, ok=True, state="open",
                svc=guess_svc(port), info="",
                elapsed=elapsed, n_cmd="", raw="", err=None,
            ))


async def scan_targets_parallel(
    targets,
    ports,
    c_conc,
    c_to,
    s_conc,
    n_args,
    svc_on,
    aggr_on,
    sudo_pw,
    stealth,
    syn_scan,
    verbose,
    target_concurrency,
    quiet,
    retries = 0,
    batch = 20,
    batch_delay_ms = 4.0,
):
    total = len(targets)
    started_all = datetime.now(timezone.utc)
    t0 = time.perf_counter()

    async def _resolve_one(target):
        try:
            ip = ipaddress.ip_address(target)
            return (target, str(ip), socket.AF_INET if ip.version == 4 else socket.AF_INET6, None)
        except ValueError:
            pass
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(target, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            for family, _st, _pr, _cn, sockaddr in infos:
                if family in (socket.AF_INET, socket.AF_INET6):
                    return (target, sockaddr[0], family, None)
            return (target, "", 0, "no supported address family")
        except Exception as err:
            return (target, "", 0, str(err))

    resolve_tasks = [asyncio.create_task(_resolve_one(t)) for t in targets]
    resolved = await asyncio.gather(*resolve_tasks)

    per_target = {}

    for target, ip, family, err in resolved:
        per_target[target] = {
            "ip": ip,
            "family": family,
            "open": [],
            "probes": {},
            "err": err,
        }

    if syn_scan:
        stream_open = None
        if not quiet:
            def stream_open(target, ip, port):
                label = target if target == ip else f"{target} ({ip})"
                print(f"  {label:<28}  →  {port}  open", flush=True)
        await bulk_syn_probe(
            per_target, resolved, ports, c_to, retries, batch, batch_delay_ms,
            on_open=stream_open,
        )
    else:
        connect_sem = asyncio.Semaphore(max(1, c_conc))

        async def _probe_one(target, ip, family, port):
            if not ip or family == 0:
                return (target, port, "closed", 0.0)
            async with connect_sem:
                t1 = time.perf_counter()
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port, family=family),
                        timeout=c_to,
                    )
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
                    except Exception:
                        pass
                    return (target, port, "open", time.perf_counter() - t1)
                except Exception:
                    return (target, port, "closed", time.perf_counter() - t1)

        probe_tasks = []
        for target, ip, family, _err in resolved:
            if not ip or family == 0:
                continue
            for port in ports:
                probe_tasks.append(asyncio.create_task(_probe_one(target, ip, family, port)))
        if probe_tasks:
            probe_results = await asyncio.gather(*probe_tasks)
            for target, port, state, elapsed in probe_results:
                if state == "open":
                    per_target[target]["open"].append(port)
                per_target[target]["probes"][port] = (state, elapsed)

    if svc_on and not aggr_on:
        svc_sem = asyncio.Semaphore(max(1, s_conc))
        svc_tasks = []
        for target, info in per_target.items():
            if not info["open"] or not info["ip"]:
                continue
            for port in info["open"]:
                svc_tasks.append(
                    asyncio.create_task(
                        bulk_svc_probe(target, info["ip"], port, svc_sem, c_to,
                                       info["family"] if info["family"] else socket.AF_INET)
                    )
                )
        if svc_tasks:
            svc_results = await asyncio.gather(*svc_tasks, return_exceptions=True)
            for res in svc_results:
                if isinstance(res, tuple) and len(res) == 3:
                    target, port, svc_hit = res
                    per_target[target]["probes"][port] = svc_hit

    results = [None] * total
    completed = 0
    t1_total = time.perf_counter()

    for i, target in enumerate(targets):
        info = per_target.get(target, {})
        ip = info.get("ip", "")
        open_ports = sorted(info.get("open", []))
        svcs = []
        for port in open_ports:
            probe_data = info.get("probes", {}).get(port)
            if isinstance(probe_data, SvcInfo):
                svcs.append(probe_data)
            else:
                svcs.append(SvcInfo(
                    port=port, ok=True, state="open",
                    svc=guess_svc(port), info="",
                    elapsed=probe_data[1] if isinstance(probe_data, tuple) else 0.0,
                    n_cmd="", raw="", err=None,
                ))

        err_str = info.get("err")
        errors = [err_str] if err_str else []
        results[i] = ScanHit(
            target=target, ip=ip,
            req_ports=list(ports),
            open_ports=open_ports,
            svcs=svcs,
            started=started_all.isoformat(),
            finished=datetime.now(timezone.utc).isoformat(),
            elapsed=round(t1_total - t0, 3),
            errors=errors,
        )
        completed += 1
        if not quiet and total > 1 and open_ports:
            ports_str = ",".join(str(p) for p in open_ports)
            print(f"  [{completed}/{total}] {target}  →  [{ports_str}]", flush=True)

    if not quiet and total > 1:
        tag = f"bulk x{target_concurrency}" if target_concurrency else "bulk (uncapped)"
        console.print(Text(f"  Targets  {total}  ·  {tag}", style=DIM))
        console.print()

    return results
