# this file contains all the  builder functions for the port scanner


import argparse
import csv
import html
import io
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from rich import box
from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ...core.results import ScanHit
from .constants import (
    BORDER,
    CYAN,
    DETAIL,
    DIM,
    DIMMER,
    GREEN,
    RED,
    SVC_COL,
    WHITE,
    YELLOW,
)
from .models import ScanCfg
from .parsers import guess_svc

console = Console(highlight=False)



# helper functions


# build live discovery table showing ports as they're found
def live_disc_tbl(open_ports: List[int], target: str) -> Table:
    tbl = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style=f"bold {WHITE}",
        border_style=CYAN,
        title=f"[bold {WHITE}]Open Ports Discovered  •  {target}[/bold {WHITE}]",
        title_style=f"bold {WHITE}",
        expand=False,
        padding=(0, 2),
    )
    tbl.add_column("PORT", style=GREEN, justify="right", width=8, no_wrap=True)
    tbl.add_column("SERVICE", style=SVC_COL, justify="left", width=20, no_wrap=True)

    if not open_ports:
        tbl.add_row(
            Text("scanning...", style=DIM, justify="center"), Text("", style=DIM)
        )
    else:
        for port in sorted(open_ports):
            svc = guess_svc(port)
            tbl.add_row(str(port), svc)

    return tbl

def _clean_text(value: str, limit: int = 0) -> str:
    text = " ".join(html.unescape(value).split())
    if limit > 0 and len(text) > limit:
        return text[: limit - 3] + "..."
    return text




# main builders functions

# build combined renderable: progress bar + discovered ports table
def build_live_panel(progress: Progress, open_ports: List[int], target: str) -> Group:
    parts = [progress]
    if open_ports:
        parts.append(Text(""))  # spacer
        parts.append(live_disc_tbl(open_ports, target))
    return Group(*parts)


def hr(title: str = "") -> None:
    if title:
        console.print(
            Rule(title=Text(f"  {title}  ", style=DIMMER), style=BORDER, align="left")
        )
    else:
        console.print(Rule(style=BORDER))


def _probe_detail_panel(scan: ScanHit, verbose: int) -> Optional[Panel]:
    if verbose <= 0 or not scan.svcs:
        return None

    lines: List[Text] = []
    for svc in sorted(scan.svcs, key=lambda item: item.port):
        head = Text.assemble(
            (f"{svc.port:>5}/tcp", f"bold {WHITE}"),
            ("  ", DIM),
            (svc.svc, SVC_COL),
            ("  ", DIM),
            (f"{svc.elapsed:.3f}s", DIM),
        )
        if svc.n_cmd:
            head.append(f"  via {svc.n_cmd}", style=DIMMER)
        if svc.err:
            head.append(f"  err={svc.err}", style=YELLOW)
        lines.append(head)
        if svc.info:
            lines.append(Text(f"      {_clean_text(svc.info, 220)}", style=DIMMER))
        if verbose > 1 and svc.raw:
            lines.append(Text(f"      raw: {_clean_text(svc.raw, 260)}", style=DETAIL))

    return Panel(
        Group(*lines),
        title=f"[bold {WHITE}]Probe Details[/bold {WHITE}]",
        border_style=BORDER,
        box=box.ROUNDED,
        expand=True,
    )


def hdr(hosts: List[str], total_ports: int, cfg: ScanCfg) -> None:
    console.print()
    hr()
    title = Text()
    title.append("  X3R0DAY", style=f"bold {CYAN}")
    title.append("  //  ", style=DIM)
    title.append("Async TCP Port Scanner", style=f"bold {WHITE}")
    if cfg.stealth:
        title.append("  ", style=DIM)
        title.append("[STEALTH]", style=f"bold {YELLOW}")
    console.print(title)
    hr()
    console.print()

    mode = (
        "aggressive (nmap)"
        if cfg.aggr_on
        else "basic (light probe)"
        if cfg.svc_on
        else "disabled"
    )
    grid = Table.grid(padding=(0, 0))
    grid.add_column(min_width=16)
    grid.add_column(min_width=28)
    grid.add_column(min_width=6)
    grid.add_column(min_width=16)
    grid.add_column()
    rows = [
        ("Target", ", ".join(hosts), "Timeout", f"{cfg.c_to:.2f}s"),
        ("Ports", f"{total_ports:,} selected", "Svc Scan", mode),
        (
            "Max Concurrency",
            str(cfg.c_conc),
            "Started",
            datetime.now().strftime("%Y-%m-%d  %H:%M:%S"),
        ),
    ]
    for k1, v1, k2, v2 in rows:
        grid.add_row(
            Text(k1, style=DIM),
            Text(v1, style=WHITE),
            Text(""),
            Text(k2, style=DIM),
            Text(v2, style=WHITE),
        )
    console.print(Padding(grid, (0, 2)))
    console.print()
    hr()
    console.print()


def mk_prog(transient: bool = True) -> Progress:
    return Progress(
        SpinnerColumn(spinner_name="dots2", style=CYAN),
        TextColumn("  [bold white]{task.description}[/bold white]"),
        BarColumn(
            bar_width=44, style=DIMMER, complete_style=CYAN, finished_style=GREEN
        ),
        TaskProgressColumn(style=DIM),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=transient,
    )


def state_label(state: str) -> Text:
    mapping = {
        "open": (GREEN, "open"),
        "closed": (RED, "closed"),
        "filtered": (YELLOW, "filtered"),
        "failed": (RED, "failed"),
    }
    style, label = mapping.get(state, (DIM, state))
    return Text(label, style=style)


def open_tbl(scan: ScanHit) -> Table:
    tbl = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {DIM}",
        border_style=BORDER,
        show_edge=True,
        expand=False,
        padding=(0, 2),
    )
    tbl.add_column("PORT", style=WHITE, justify="right", width=7, no_wrap=True)
    tbl.add_column("PROTO", style=DIM, justify="center", width=7, no_wrap=True)
    tbl.add_column("STATE", justify="left", width=10, no_wrap=True)
    tbl.add_column("SERVICE", style=SVC_COL, justify="left", width=20, no_wrap=True)
    tbl.add_column("DETAILS", style=DETAIL, justify="left", min_width=30, max_width=55)

    svc_map = {s.port: s for s in scan.svcs}
    for port in scan.open_ports:
        svc_hit = svc_map.get(port)
        service = svc_hit.svc if svc_hit else "unknown"
        info = svc_hit.info if svc_hit else ""
        state = svc_hit.state if svc_hit else "open"
        if info:
            info = " ".join(info.split())
        if len(info) > 55:
            info = info[:52] + "..."
        tbl.add_row(str(port), "tcp", state_label(state), service, info)
    return tbl


def sum_tbl(scan: ScanHit) -> Table:
    total = len(scan.req_ports)
    opened = len(scan.open_ports)
    filtered = getattr(scan, "_filtered_count", 0)
    closed = getattr(scan, "_closed_count", max(total - opened - filtered, 0))
    pct = opened / total * 100 if total > 0 else 0.0
    ts = scan.started[:19].replace("T", "  ")
    tf = scan.finished[:19].replace("T", "  ")
    grid = Table.grid(padding=(0, 4))
    for width in (13, 20, 13, 22, 13, 18):
        grid.add_column(min_width=width, no_wrap=True)
    key = lambda value: Text(value, style=DIM)
    val = lambda value: Text(value, style=WHITE)
    grid.add_row(
        key("Scanned"),
        val(f"{total:,} ports"),
        key("Elapsed"),
        val(f"{scan.elapsed:.3f}s"),
        key("Target"),
        val(scan.target),
    )
    grid.add_row(
        key("Open"),
        val(f"{opened}  [{pct:.1f}%]"),
        key("Started"),
        val(ts),
        key("IP"),
        val(scan.ip),
    )
    grid.add_row(
        key("Closed"),
        val(str(closed)),
        key("Filtered"),
        val(str(filtered)),
        key("Finished"),
        val(tf),
    )
    return grid


def show_scan(scan: ScanHit, idx: int = 0, total: int = 1, verbose: int = 0) -> None:
    console.print()
    if total > 1:
        hr(f"Target {idx + 1}/{total}")
    console.print(
        Panel(
            Padding(sum_tbl(scan), (0, 1)),
            title=f"[bold {WHITE}]Scan Summary[/bold {WHITE}]",
            border_style=BORDER,
            box=box.ROUNDED,
            expand=True,
        )
    )
    if scan.open_ports:
        content = Padding(open_tbl(scan), (0, 1))
        border = CYAN
    else:
        content = Padding(
            Text("No open ports discovered in selected range.", style=DIM), (0, 1)
        )
        border = BORDER
    console.print(
        Panel(
            content,
            title=f"[bold {WHITE}]Open Ports  •  {scan.target}[/bold {WHITE}]",
            border_style=border,
            box=box.ROUNDED,
            expand=True,
        )
    )
    detail_panel = _probe_detail_panel(scan, verbose)
    if detail_panel is not None:
        console.print(detail_panel)
    console.print()


def show_multi_sum(runs: List[ScanHit]) -> None:
    if len(runs) < 2:
        return
    console.print()
    hr("Aggregate Summary")
    console.print()
    tbl = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {DIM}",
        border_style=BORDER,
        expand=False,
        padding=(0, 2),
    )
    tbl.add_column("#", style=DIM, justify="right", width=4)
    tbl.add_column("TARGET", style=WHITE, justify="left", min_width=26)
    tbl.add_column("IP", style=DIM, justify="left", min_width=16)
    tbl.add_column("OPEN", justify="right", width=7)
    tbl.add_column("SCANNED", style=DIM, justify="right", width=9)
    tbl.add_column("ELAPSED", style=DIM, justify="right", width=10)
    total_open = 0
    total_scanned = 0
    for i, scan in enumerate(runs, 1):
        opened = len(scan.open_ports)
        total_open += opened
        total_scanned += len(scan.req_ports)
        tbl.add_row(
            str(i),
            scan.target,
            scan.ip,
            Text(str(opened), style=GREEN if opened > 0 else DIM),
            f"{len(scan.req_ports):,}",
            f"{scan.elapsed:.3f}s",
        )
    tbl.add_section()
    tbl.add_row(
        "",
        Text("TOTAL", style=DIM),
        "",
        Text(str(total_open), style=f"bold {GREEN}"),
        Text(f"{total_scanned:,}", style="bold"),
        "",
    )
    console.print(Padding(tbl, (0, 2)))
    console.print()
    hr()
    console.print()


def out_mode(raw: str):
    out = Path(raw)
    if not out.suffix:
        return out.with_name(out.name + ".html"), "html"
    if out.suffix.lower() == ".json":
        return out, "json"
    if out.suffix.lower() == ".csv":
        return out, "csv"
    return out, "html"


def scan_csv(runs: List[ScanHit]) -> str:
    buf = io.StringIO()
    fields = [
        "target",
        "ip",
        "port",
        "proto",
        "state",
        "service",
        "details",
        "probe_elapsed",
        "probe_cmd",
        "probe_error",
        "scan_started",
        "scan_finished",
        "scan_elapsed",
        "scanned",
        "open_count",
        "closed_count",
        "filtered_count",
    ]
    writer = csv.DictWriter(buf, fieldnames=fields)
    writer.writeheader()
    for scan in runs:
        total = len(scan.req_ports)
        opened = len(scan.open_ports)
        filtered = getattr(scan, "_filtered_count", 0)
        closed = getattr(scan, "_closed_count", max(total - opened - filtered, 0))
        svc_map = {svc.port: svc for svc in scan.svcs}
        for port in scan.open_ports or [0]:
            svc = svc_map.get(port)
            writer.writerow(
                {
                    "target": scan.target,
                    "ip": scan.ip,
                    "port": port or "",
                    "proto": "tcp" if port else "",
                    "state": svc.state if svc else "",
                    "service": svc.svc if svc else "",
                    "details": _clean_text(svc.info, 500) if svc else "",
                    "probe_elapsed": f"{svc.elapsed:.3f}" if svc else "",
                    "probe_cmd": svc.n_cmd if svc else "",
                    "probe_error": svc.err if svc and svc.err else "",
                    "scan_started": scan.started,
                    "scan_finished": scan.finished,
                    "scan_elapsed": f"{scan.elapsed:.3f}",
                    "scanned": total,
                    "open_count": opened,
                    "closed_count": closed,
                    "filtered_count": filtered,
                }
            )
    return buf.getvalue()


# build unified html report
def build_scan_html(runs: List[ScanHit]) -> str:
    lines = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "  <meta charset='utf-8'>",
        "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        "  <title>X3R0DAY Scan Report</title>",
        "  <style>",
        "    * { box-sizing: border-box; margin: 0; padding: 0; }",
        "    body {",
        "      font-family: system-ui, -apple-system, sans-serif;",
        "      background: #121212;",
        "      color: #d4d4d4;",
        "      font-size: 14px;",
        "      line-height: 1.5;",
        "      padding: 24px;",
        "    }",
        "    .wrap { max-width: 900px; margin: 0 auto; }",
        "    h1 {",
        "      font-size: 16px;",
        "      font-weight: 600;",
        "      color: #e0e0e0;",
        "      margin-bottom: 8px;",
        "    }",
        "    .meta { font-size: 12px; color: #707070; margin-bottom: 24px; }",
        "    hr { border: none; border-top: 1px solid #2a2a2a; margin: 24px 0; }",
        "    .target { margin-bottom: 16px; }",
        "    .target-name { font-size: 15px; font-weight: 500; color: #c0c0c0; }",
        "    .target-ip { font-size: 12px; color: #606060; margin-top: 2px; }",
        "    .stats { display: flex; gap: 24px; font-size: 13px; margin-bottom: 20px; }",
        "    .stats span { color: #606060; }",
        "    .stats strong { color: #a0a0a0; margin-left: 4px; }",
        "    .stats .open strong { color: #6a9955; }",
        "    table { width: 100%; border-collapse: collapse; }",
        "    th {",
        "      text-align: left;",
        "      font-size: 11px;",
        "      font-weight: 500;",
        "      color: #606060;",
        "      padding: 8px 12px;",
        "      border-bottom: 1px solid #2a2a2a;",
        "    }",
        "    td {",
        "      padding: 10px 12px;",
        "      border-bottom: 1px solid #1e1e1e;",
        "      vertical-align: top;",
        "    }",
        "    .port { font-family: monospace; color: #9cdcfe; }",
        "    .state { color: #6a9955; }",
        "    .service { color: #ce9178; }",
        "    .info { font-size: 12px; color: #606060; }",
        "    details { margin-top: 4px; }",
        "    summary {",
        "      color: #505050;",
        "      cursor: pointer;",
        "      font-size: 11px;",
        "      list-style: none;",
        "      display: flex;",
        "      align-items: center;",
        "      gap: 4px;",
        "    }",
        "    summary::-webkit-details-marker { display: none; }",
        "    summary::before { content: '▶'; font-size: 8px; transition: transform 0.1s; }",
        "    details[open] summary::before { transform: rotate(90deg); }",
        "    .detail-box {",
        "      margin-top: 8px;",
        "      padding: 12px;",
        "      background: #1a1a1a;",
        "      border: 1px solid #2a2a2a;",
        "      border-radius: 4px;",
        "      font-family: monospace;",
        "      font-size: 12px;",
        "      color: #808080;",
        "      white-space: pre-wrap;",
        "      word-break: break-all;",
        "      max-height: 200px;",
        "      overflow-y: auto;",
        "    }",
        "    .empty { color: #606060; font-size: 13px; padding: 16px 0; }",
        "  </style>",
        "</head>",
        "<body>",
        "  <div class='wrap'>",
        "    <h1>Port Scan Report</h1>",
        f"    <p class='meta'>X3R0DAY Specter &middot; {len(runs)} target(s) &middot; {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>",
    ]

    for scan in runs:
        total = len(scan.req_ports)
        opened = len(scan.open_ports)
        filtered = getattr(scan, "_filtered_count", 0)
        closed = getattr(scan, "_closed_count", max(total - opened - filtered, 0))

        lines.append("    <hr>")
        lines.append("    <div class='target'>")
        lines.append(f"      <div class='target-name'>{html.escape(scan.target)}</div>")
        lines.append(f"      <div class='target-ip'>{html.escape(scan.ip)}</div>")
        lines.append("    </div>")

        lines.append("    <div class='stats'>")
        lines.append(f"      <span>Scanned<strong>{total:,}</strong></span>")
        lines.append(f"      <span class='open'>Open<strong>{opened}</strong></span>")
        lines.append(f"      <span>Closed<strong>{closed}</strong></span>")
        lines.append(f"      <span>Filtered<strong>{filtered}</strong></span>")
        lines.append(f"      <span>{scan.elapsed:.2f}s</span>")
        lines.append("    </div>")

        if scan.open_ports:
            svc_map = {s.port: s for s in scan.svcs}
            lines.append("    <table>")
            lines.append(
                "      <thead><tr><th style='width:70px'>Port</th><th style='width:60px'>State</th><th style='width:120px'>Service</th><th>Info</th></tr></thead>"
            )
            lines.append("      <tbody>")

            for port in scan.open_ports:
                sv = svc_map.get(port)
                svc = sv.svc if sv else "unknown"
                info_short = _clean_text(sv.info, 80) if sv and sv.info else ""
                info_full = sv.info if sv and sv.info else ""

                lines.append("      <tr>")
                lines.append(f"        <td class='port'>{port}</td>")
                lines.append("        <td class='state'>open</td>")
                lines.append(f"        <td class='service'>{html.escape(svc)}</td>")
                lines.append("        <td class='info'>")

                if len(info_full) > 80:
                    lines.append(f"          {html.escape(info_short)}")
                    lines.append("          <details>")
                    lines.append("            <summary>show more</summary>")
                    lines.append(
                        f"            <div class='detail-box'>{html.escape(info_full)}</div>"
                    )
                    lines.append("          </details>")
                else:
                    lines.append(f"          {html.escape(info_short)}")

                lines.append("        </td>")
                lines.append("      </tr>")

            lines.append("      </tbody>")
            lines.append("    </table>")
        else:
            lines.append("    <p class='empty'>No open ports found</p>")

    lines.append("  </div>")
    lines.append("</body>")
    lines.append("</html>")

    return "\n".join(lines)


# build argument parser
def build_parser(prog: Optional[str] = None) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description="async tcp port scanner with realtime per-port service detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("target", nargs="*", help="target hostnames / ips")
    p.add_argument("-iL", "--input-file", default=None, help="read targets from file, one per line")
    p.add_argument("-p", "--ports", default=None, help="ports: 22,80,443  or  1-1024")
    p.add_argument(
        "-P",
        "--top-ports",
        type=int,
        choices=[100, 1000],
        default=1000,
        help="nmap top tcp ports by frequency (default: 1000)",
    )
    p.add_argument(
        "-a", "--all-ports", action="store_true", help="scan all tcp ports 1-65535"
    )
    p.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=1000,
        help="max concurrent tcp connect limit (default: 1000)",
    )
    p.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.5,
        help="max tcp connect timeout in seconds (default: 1.5)",
    )
    p.add_argument(
        "-C",
        "--svc-concurrency",
        type=int,
        default=20,
        help="concurrent service scan limit (default: 20)",
    )
    p.add_argument(
        "-T",
        "--target-concurrency",
        type=int,
        default=0,
        metavar="N",
        help="max concurrent targets (default: 0 = unlimited, adaptive backpressure)",
    )
    p.add_argument(
        "-R",
        "--retries",
        type=int,
        default=1,
        metavar="N",
        help="retries/retransmit rounds for unanswered probes (default: 1; higher finds more hosts on lossy links)",
    )
    p.add_argument(
        "-A",
        "--agents",
        type=int,
        default=0,
        metavar="N",
        help="spawn N WARP agents to split scan across unique IPs (requires docker)",
    )
    p.add_argument(
        "--batch",
        type=int,
        default=20,
        metavar="N",
        help="SYN scan: packets to send per burst before pausing (default: 20)",
    )
    p.add_argument(
        "--batch-delay",
        type=float,
        default=4.0,
        metavar="MS",
        help="SYN scan: pause in milliseconds between bursts (default: 4.0)",
    )
    p.add_argument(
        "-S",
        "--aggr-svc-scan",
        action="store_true",
        help="aggressive nmap service scan (-sV -A) on open ports",
    )
    p.add_argument(
        "-M",
        "--nmap-args",
        default="-sV --open",
        help="extra nmap args for -S mode",
    )
    p.add_argument(
        "-U",
        "--sudo-nmap",
        action="store_true",
        help="prompt for sudo; run nmap with elevated privileges and prefer nmap service detection",
    )
    p.add_argument(
        "-N",
        "--no-svc-scan",
        action="store_true",
        help="tcp open-port detection only, skip service identification",
    )
    p.add_argument(
        "--stealth",
        action="store_true",
        help="enable low-noise mode: smaller windows and fewer app-layer probes",
    )
    scan_mode = p.add_mutually_exclusive_group()
    scan_mode.add_argument(
        "--syn-scan",
        action="store_true",
        help="use raw TCP SYN scan (requires root)",
    )
    scan_mode.add_argument(
        "--connect-scan",
        action="store_true",
        help="use full TCP connect scan",
    )
    p.add_argument(
        "-o",
        "--out",
        default=None,
        help="write results to file (HTML by default, JSON if filename ends with .json)",
    )
    p.add_argument(
        "-v",
        action="count",
        default=0,
        help="show extra probe detail (-vv includes raw probe snippets)",
    )
    p.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress scan-time banners and progress chatter",
    )
    return p
