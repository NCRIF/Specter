# this file contains all the  builder functions for the subdomain


import csv
import html
import io
from datetime import datetime
from pathlib import Path

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

from .constants import BORDER, CYAN, DETAIL, DIM, DIMMER, GREEN, RED, SVC_COL, WHITE, YELLOW
from .models import SubCfg, SubHit, SubRun

console = Console(highlight=False)


def hr(title = ""):
    if title:
        console.print(
            Rule(title=Text(f"  {title}  ", style=DIMMER), style=BORDER, align="left")
        )
    else:
        console.print(Rule(style=BORDER))


def hdr(domain, cfg):
    console.print()
    hr()
    title = Text()
    title.append("  X3R0DAY", style=f"bold {CYAN}")
    title.append("  //  ", style=DIM)
    title.append("Async Subdomain Enumerator", style=f"bold {WHITE}")
    console.print(title)
    hr()
    console.print()
    sources = ["crt.sh", "hackertarget", "alienvault", "urlscan", "rapiddns"]
    if cfg.shodan_key:
        sources.insert(0, "shodan")
    if cfg.brute:
        sources.append("bruteforce")
    rows = [
        ("Domain", domain, "Port Scan", "enabled" if cfg.nmap_on else "disabled"),
        ("Sources", ", ".join(sources), "Scrape", "enabled" if cfg.scrape_on else "disabled"),
        (
            "Resolve",
            f"{cfg.resolve_c} concurrent",
            "Started",
            datetime.now().strftime("%Y-%m-%d  %H:%M:%S"),
        ),
    ]
    grid = Table.grid(padding=(0, 0))
    for width in (16, 38, 6, 16, 1):
        grid.add_column(min_width=width)
    for key1, val1, key2, val2 in rows:
        grid.add_row(
            Text(key1, style=DIM),
            Text(val1, style=WHITE),
            Text(""),
            Text(key2, style=DIM),
            Text(val2, style=WHITE),
        )
    console.print(Padding(grid, (0, 2)))
    console.print()
    hr()
    console.print()


def mk_prog(transient = True):
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


def live_disc_tbl(subs, domain):
    tbl = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style=f"bold {WHITE}",
        border_style=CYAN,
        title=f"[bold {WHITE}]Subdomains Discovered  •  {domain}[/bold {WHITE}]",
        title_style=f"bold {WHITE}",
        expand=False,
        padding=(0, 2),
    )
    tbl.add_column("SUBDOMAIN", style=GREEN, justify="left", min_width=40, no_wrap=True)
    tbl.add_column("IP", style=DIM, justify="left", width=16, no_wrap=True)
    tbl.add_column("SOURCES", style=SVC_COL, justify="left", min_width=20, no_wrap=True)
    if not subs:
        tbl.add_row(Text("enumerating...", style=DIM), Text(""), Text(""))
    else:
        for sub in subs[-18:]:
            tbl.add_row(
                sub.subdomain, sub.ip or "resolving...", ", ".join(sub.sources[:3])
            )
    return tbl


def build_live_panel(progress, subs, domain):
    parts = [progress]
    if subs:
        parts.append(Text(""))
        parts.append(live_disc_tbl(subs, domain))
    return Group(*parts)


def _status_style(code):
    if code == 0:
        return DIM, "-"
    if 200 <= code < 300:
        return GREEN, str(code)
    if 300 <= code < 400:
        return YELLOW, str(code)
    if code >= 400:
        return RED, str(code)
    return DIM, str(code)


def _fmt_display_ts(raw):
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return raw[:19].replace("T", "  ")
    if dt.tzinfo is not None:
        dt = dt.astimezone()
    return dt.strftime("%Y-%m-%d  %H:%M:%S")


def sub_tbl(run):
    tbl = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style=f"bold {DIM}",
        border_style=BORDER,
        show_edge=True,
        expand=False,
        padding=(0, 2),
    )
    tbl.add_column("SUBDOMAIN", style=WHITE, justify="left", min_width=34, no_wrap=True)
    tbl.add_column("IP", style=DIM, justify="left", width=16, no_wrap=True)
    tbl.add_column("PORTS", style=GREEN, justify="left", width=24, no_wrap=True)
    tbl.add_column("STATUS", justify="center", width=8, no_wrap=True)
    tbl.add_column("TITLE", style=DETAIL, justify="left", min_width=28, max_width=46)
    tbl.add_column("SERVER", style=DIM, justify="left", min_width=12, max_width=20)
    for sub in run.subdomains:
        style, status = _status_style(sub.status)
        title = sub.title.strip()
        if len(title) > 46:
            title = title[:43] + "..."
        tbl.add_row(
            sub.subdomain,
            sub.ip or Text("unresolved", style=DIM),
            ", ".join(str(port) for port in sub.ports) if sub.ports else "-",
            Text(status, style=style),
            title or Text("-", style=DIM),
            sub.server[:20] if sub.server else "-",
        )
    return tbl


def sum_tbl(run):
    web_hits = sum(1 for sub in run.subdomains if sub.ports)
    grid = Table.grid(padding=(0, 4))
    for width in (13, 20, 13, 22, 13, 18):
        grid.add_column(min_width=width, no_wrap=True)
    key = lambda value: Text(value, style=DIM)
    val = lambda value: Text(value, style=WHITE)
    grid.add_row(
        key("Found"),
        val(f"{run.total_found:,} subdomains"),
        key("Elapsed"),
        val(f"{run.elapsed:.3f}s"),
        key("Domain"),
        val(run.domain),
    )
    grid.add_row(
        key("Resolved"),
        val(str(run.total_resolved)),
        key("Started"),
        val(_fmt_display_ts(run.started)),
        key("Web Ports"),
        val(str(web_hits)),
    )
    grid.add_row(
        key("No DNS"),
        val(str(run.total_found - run.total_resolved)),
        key("Finished"),
        val(_fmt_display_ts(run.finished)),
        key(""),
        val(""),
    )
    return grid


def show_run(run):
    console.print()
    console.print(
        Panel(
            Padding(sum_tbl(run), (0, 1)),
            title=f"[bold {WHITE}]Scan Summary[/bold {WHITE}]",
            border_style=BORDER,
            box=box.ROUNDED,
            expand=True,
        )
    )
    content = (
        Padding(sub_tbl(run), (0, 1))
        if run.subdomains
        else Padding(Text("No subdomains discovered.", style=DIM), (0, 1))
    )
    console.print(
        Panel(
            content,
            title=f"[bold {WHITE}]Subdomains  •  {run.domain}[/bold {WHITE}]",
            border_style=CYAN if run.subdomains else BORDER,
            box=box.ROUNDED,
            expand=True,
        )
    )
    console.print()


def out_mode(raw):
    out = Path(raw)
    if not out.suffix:
        return out.with_name(out.name + ".html"), "html"
    if out.suffix.lower() == ".json":
        return out, "json"
    if out.suffix.lower() == ".csv":
        return out, "csv"
    return out, "html"


def sub_csv(run):
    buf = io.StringIO()
    fields = [
        "domain", "subdomain", "ip", "sources", "ports", "status", "title",
        "server", "tech", "elapsed", "err",
    ]
    writer = csv.DictWriter(buf, fieldnames=fields)
    writer.writeheader()
    rows = run.subdomains or [
        SubHit("", "", [], [], 0, "", "", [], 0.0, "")
    ]
    for sub in rows:
        writer.writerow(
            {
                "domain": run.domain,
                "subdomain": sub.subdomain,
                "ip": sub.ip,
                "sources": "|".join(sub.sources),
                "ports": ",".join(str(port) for port in sub.ports),
                "status": sub.status,
                "title": sub.title,
                "server": sub.server,
                "tech": "|".join(sub.tech),
                "elapsed": sub.elapsed,
                "err": sub.err or "",
            }
        )
    return buf.getvalue()


def build_sub_html(run):
    found = run.total_found
    resolved = run.total_resolved
    web_hits = sum(1 for sub in run.subdomains if sub.ports)
    lines = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "  <meta charset='utf-8'>",
        "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        "  <title>X3R0DAY Subdomain Report</title>",
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
        "    .wrap { max-width: 1100px; margin: 0 auto; }",
        "    h1 {",
        "      font-size: 16px;",
        "      font-weight: 600;",
        "      color: #e0e0e0;",
        "      margin-bottom: 8px;",
        "    }",
        "    .meta { font-size: 12px; color: #707070; margin-bottom: 24px; }",
        "    hr { border: none; border-top: 1px solid #2a2a2a; margin: 24px 0; }",
        "    .domain { margin-bottom: 16px; }",
        "    .domain-name { font-size: 15px; font-weight: 500; color: #c0c0c0; }",
        "    .stats { display: flex; gap: 24px; font-size: 13px; margin-bottom: 20px; }",
        "    .stats span { color: #606060; }",
        "    .stats strong { color: #a0a0a0; margin-left: 4px; }",
        "    .stats .hits strong { color: #6a9955; }",
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
        "    .sub { color: #9cdcfe; word-break: break-all; }",
        "    .ip { font-family: monospace; color: #808080; font-size: 13px; }",
        "    .status-2 { color: #6a9955; }",
        "    .status-3 { color: #dcdcaa; }",
        "    .status-4 { color: #f14c4c; }",
        "    .ports { font-family: monospace; color: #808080; font-size: 12px; }",
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
        "    <h1>Subdomain Report</h1>",
        f"    <p class='meta'>X3R0DAY Specter &middot; {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>",
    ]

    lines.append("    <hr>")
    lines.append("    <div class='domain'>")
    lines.append(f"      <div class='domain-name'>{html.escape(run.domain)}</div>")
    lines.append("    </div>")
    lines.append("    <div class='stats'>")
    lines.append(f"      <span>Found<strong>{found}</strong></span>")
    lines.append(f"      <span>Resolved<strong>{resolved}</strong></span>")
    lines.append(f"      <span>No DNS<strong>{max(found - resolved, 0)}</strong></span>")
    lines.append(f"      <span class='hits'>Web Hits<strong>{web_hits}</strong></span>")
    lines.append(f"      <span>{run.elapsed:.2f}s</span>")
    lines.append("    </div>")

    if not run.subdomains:
        lines.append("    <p class='empty'>No subdomains discovered</p>")
    else:
        lines.append("    <table>")
        lines.append(
            "      <thead><tr><th>Subdomain</th><th style='width:120px'>IP</th><th style='width:80px'>Status</th><th style='width:100px'>Ports</th><th>Info</th></tr></thead>"
        )
        lines.append("      <tbody>")
        for sub in run.subdomains:
            status_cls = "info"
            if 200 <= sub.status < 300:
                status_cls = "status-2"
            elif 300 <= sub.status < 400:
                status_cls = "status-3"
            elif sub.status >= 400:
                status_cls = "status-4"
            status_str = str(sub.status) if sub.status else "-"
            ports_str = ", ".join(str(port) for port in sub.ports) if sub.ports else "-"
            title_short = sub.title[:60] + "..." if len(sub.title) > 60 else sub.title
            title_full = sub.title
            lines.append("      <tr>")
            lines.append(f"        <td class='sub'>{html.escape(sub.subdomain)}</td>")
            lines.append(f"        <td class='ip'>{html.escape(sub.ip or '-')}</td>")
            lines.append(f"        <td class='{status_cls}'>{status_str}</td>")
            lines.append(f"        <td class='ports'>{html.escape(ports_str)}</td>")
            lines.append("        <td class='info'>")
            if len(title_full) > 60:
                lines.append(f"          {html.escape(title_short)}")
                lines.append("          <details>")
                lines.append("            <summary>show more</summary>")
                lines.append(
                    f"            <div class='detail-box'>Title: {html.escape(title_full)}"
                )
                if sub.server:
                    lines.append(f"Server: {html.escape(sub.server)}")
                if sub.tech:
                    lines.append(f"Tech: {html.escape(', '.join(sub.tech))}")
                if sub.err:
                    lines.append(f"Error: {html.escape(sub.err)}")
                lines.append("            </div>")
                lines.append("          </details>")
            else:
                info_parts = []
                if sub.title:
                    info_parts.append(sub.title)
                if sub.server:
                    info_parts.append(f"({sub.server})")
                lines.append(f"          {html.escape(' '.join(info_parts) or '-')}")
            lines.append("        </td>")
            lines.append("      </tr>")
        lines.append("      </tbody>")
        lines.append("    </table>")

    if run.errors:
        lines.append("    <details style='margin-top: 16px;'>")
        lines.append("      <summary>Show Errors</summary>")
        lines.append("      <div class='detail-box'>")
        for err in run.errors:
            lines.append(html.escape(err))
        lines.append("      </div>")
        lines.append("    </details>")
    lines.append("  </div>")
    lines.append("</body>")
    lines.append("</html>")
    return "\n".join(lines)
