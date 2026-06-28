# async subdomain enumerator


import asyncio
import io
import json
import re
import socket
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from rich.console import Console
from rich.live import Live
from rich.progress import Progress
from rich.text import Text

from ..libs.subdomain.builders import (
    build_live_panel,
    build_sub_html,
    console,
    hdr,
    hr,
    live_disc_tbl,
    mk_prog,
    out_mode as _out_mode,
    show_run,
    sub_csv as _sub_csv,
    sub_tbl,
    sum_tbl,
)
from ..libs.subdomain.constants import (
    ALIENVAULT_URL,
    CRTSH_URL,
    CYAN,
    DIM,
    DIMMER,
    GREEN,
    HACKERTARGET_URL,
    HTTP_TO,
    HTTP_W_MAX,
    HTTP_W_MIN,
    RAPIDDNS_URL,
    RED,
    SCAN_TO,
    SHODAN_DNS_URL,
    SVC_COL,
    URLSCAN_URL,
    WEB_PORTS,
    WHITE,
    WORDLIST,
    YELLOW,
)
from ..libs.subdomain.dns import DnsFallback as _DnsFallback
from ..libs.subdomain.dns import DnsResolver as _Dns
from ..libs.subdomain.http import TitleParser as _TitleParser
from ..libs.subdomain.http import http_get as _http_get
from ..libs.subdomain.models import Cfg, SubCfg, SubHit, SubInfo, SubRun, SubScanOut
from ..libs.subdomain.parser import build_parser
from .port_scan import scan_quiet

# all of the contsants are saved in ../subdomains/constants.py
# edit constants.py to configure default values

# Workflow implementation remains in scanner
# helpers are located in ../libs/subdomain.

class SubScanner:
    def __init__(self, cfg):
        self.cfg = cfg
        self._found = set()
        self._lock = asyncio.Lock()
        self._resolve_sem = asyncio.Semaphore(cfg.resolve_c)
        self._nmap_sem = asyncio.Semaphore(cfg.nmap_c)
        self._http_w = max(HTTP_W_MIN, min(HTTP_W_MAX, cfg.resolve_c))
        self._http_sem = asyncio.Semaphore(self._http_w)
        self._http_pool = ThreadPoolExecutor(
            max_workers=self._http_w, thread_name_prefix="sub-http"
        )
        self._dns_pool = ThreadPoolExecutor(
            max_workers=max(4, min(32, cfg.resolve_c)),
            thread_name_prefix="sub-dns-fallback",
        )
        self._dns = _Dns()
        self._res_cache = {}
        self._errors = []
        self._total_raw = 0

    def _v(self, msg):
        if self.cfg.verbose > 0 and not self.cfg.quiet:
            console.print(Text(f"  {msg}", style=DIMMER))

    def _err(self, msg):
        self._errors.append(msg)
        if self.cfg.verbose > 0 and not self.cfg.quiet:
            console.print(Text(f"  !  {msg}", style=YELLOW))

    # keep blocking urllib work off the event loop
    async def _aget(
        self,
        url,
        to = HTTP_TO,
        max_b = 5 << 20,
    ):
        async with self._http_sem:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                self._http_pool, lambda: _http_get(url, to, max_b)
            )

    # libc fallback for truncated replies or dns servers that misbehave
    async def _sys_resolve(self, host):
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.run_in_executor(
                    self._dns_pool,
                    lambda: socket.getaddrinfo(
                        host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
                    ),
                ),
                timeout=4.0,
            )
        except Exception:
            return ""

        for family, _socktype, _proto, _canonname, sockaddr in infos:
            if family in {socket.AF_INET, socket.AF_INET6}:
                return sockaddr[0]
        return ""

    def close(self):
        self._http_pool.shutdown(wait=False, cancel_futures=True)
        self._dns_pool.shutdown(wait=False, cancel_futures=True)

    async def _src_crtsh(self, domain):
        url = CRTSH_URL.format(d=domain)
        try:
            # crt.sh can be painfully slow on larger domains
            code, body, _, err = await self._aget(url, to=90.0, max_b=-1)
            if not body:
                self._err(f"crt.sh: empty response (http {code}), {err}")
                return []
            rows = json.loads(body.decode("utf-8", errors="replace"))
            subs = set()
            for row in rows:
                for val in str(row.get("name_value", "")).splitlines():
                    val = val.strip().lower().lstrip("*.")
                    if val.endswith(f".{domain}") or val == domain:
                        subs.add(val)
            return [(s, "crt.sh") for s in subs]
        except json.JSONDecodeError as exc:
            self._err(f"crt.sh: JSON parse error, {exc}")
            return []
        except Exception as exc:
            self._err(f"crt.sh: {exc}")
            return []

    async def _src_hackertarget(self, domain):
        url = HACKERTARGET_URL.format(d=domain)
        try:
            code, body, _, err = await self._aget(url)
            if not body:
                self._err(f"hackertarget: empty response (http {code}), {err}")
                return []
            text = body.decode("utf-8", errors="replace").strip()
            if text.lower().startswith("error") or "api count" in text.lower():
                self._err(f"hackertarget: rate limited, {text[:80]}")
                return []
            subs = set()
            for line in text.splitlines():
                parts = line.split(",")
                if parts:
                    s = parts[0].strip().lower()
                    if s.endswith(f".{domain}") or s == domain:
                        subs.add(s)
            return [(s, "hackertarget") for s in subs]
        except Exception as exc:
            self._err(f"hackertarget: {exc}")
            return []

    async def _src_alienvault(self, domain):
        url = ALIENVAULT_URL.format(d=domain)
        try:
            code, body, _, err = await self._aget(url)
            if not body:
                self._err(f"alienvault: empty response (http {code}) {err}")
                return []
            data = json.loads(body.decode("utf-8", errors="replace"))
            subs = set()
            for rec in data.get("passive_dns", []):
                hostname = str(rec.get("hostname", "")).strip().lower()
                if hostname.endswith(f".{domain}") or hostname == domain:
                    subs.add(hostname)
            return [(s, "alienvault") for s in subs]
        except json.JSONDecodeError as exc:
            self._err(f"alienvault: JSON parse error, {exc}")
            return []
        except Exception as exc:
            self._err(f"alienvault: {exc}")
            return []

    async def _src_urlscan(self, domain):
        url = URLSCAN_URL.format(d=domain)
        try:
            code, body, _, err = await self._aget(url)
            if not body:
                self._err(f"urlscan: empty response (http {code}) {err}")
                return []
            data = json.loads(body.decode("utf-8", errors="replace"))
            subs = set()
            for result in data.get("results", []):
                for key in ("task", "page"):
                    dm = result.get(key, {}).get("domain", "")
                    if dm.endswith(f".{domain}") or dm == domain:
                        subs.add(dm.lower())
            return [(s, "urlscan") for s in subs]
        except json.JSONDecodeError as exc:
            self._err(f"urlscan: JSON parse error, {exc}")
            return []
        except Exception as exc:
            self._err(f"urlscan: {exc}")
            return []

    async def _src_rapiddns(self, domain):
        url = RAPIDDNS_URL.format(d=domain)
        try:
            code, body, _, err = await self._aget(url)
            if not body:
                self._err(f"rapiddns: empty response (http {code}) {err}")
                return []
            text = body.decode("utf-8", errors="replace")
            subs = set()
            pat = r"<td[^>]*>\s*([\w.\-]+\." + re.escape(domain) + r")\s*</td>"
            for m in re.finditer(pat, text):
                s = m.group(1).strip().lower()
                if s.endswith(f".{domain}") or s == domain:
                    subs.add(s)
            # fallback: plain-text lines
            for line in text.splitlines():
                line = line.strip().lower()
                if line.endswith(f".{domain}") and re.match(r"^[\w.\-]+$", line):
                    subs.add(line)
            return [(s, "rapiddns") for s in subs]
        except Exception as exc:
            self._err(f"rapiddns: {exc}")
            return []

    async def _src_shodan(self, domain, key):
        url = SHODAN_DNS_URL.format(d=domain, k=key)
        try:
            code, body, _, err = await self._aget(url)
            if not body:
                self._err(f"shodan: empty response (http {code}) {err}")
                return []
            data = json.loads(body.decode("utf-8", errors="replace"))
            if "error" in data:
                self._err(f"shodan: {data['error']}")
                return []
            subs = set()
            for sub in data.get("subdomains", []):
                subs.add(f"{sub}.{domain}".lower())
            for rec in data.get("data", []):
                subdomain = rec.get("subdomain", "")
                if subdomain:
                    subs.add(f"{subdomain}.{domain}".lower())
            return [(s, "shodan") for s in subs]
        except json.JSONDecodeError as exc:
            self._err(f"shodan: JSON parse error, {exc}")
            return []
        except Exception as exc:
            self._err(f"shodan: {exc}")
            return []

    async def _src_brute(self, domain, words):
        results = []
        lock = asyncio.Lock()

        async def _try(word):
            candidate = f"{word}.{domain}"
            async with self._lock:
                if candidate in self._found:
                    return
            if await self._resolve(candidate):
                async with lock:
                    results.append((candidate, "bruteforce"))

        await asyncio.gather(*[_try(w) for w in words])
        return results

    # dns resolution

    async def _resolve(self, host):
        if host in self._res_cache:
            return self._res_cache[host]

        async with self._resolve_sem:
            try:
                if host in self._res_cache:
                    return self._res_cache[host]

                try:
                    ip = await self._dns.resolve(host)
                except _DnsFallback:
                    ip = await self._sys_resolve(host)

                self._res_cache[host] = ip
                return ip
            except Exception:
                self._res_cache[host] = ""
                return ""

    async def _scan_web(self, sub, ip):
        if not self.cfg.nmap_on:
            return []

        async with self._nmap_sem:
            try:
                res = await scan_quiet(
                    sub,
                    WEB_PORTS,
                    rip=ip,
                    concurrency=len(WEB_PORTS),
                    timeout=SCAN_TO,
                )
            except Exception as exc:
                self._err(f"port scan [{sub}]: {exc}")
                return []

            for err in res.errors:
                self._err(f"port scan [{sub}]: {err}")
            if self.cfg.verbose > 0:
                ports = ", ".join(str(p) for p in sorted(res.open_ports)) or "-"
                self._v(f"scan  {sub}  ->  {ports}")
            return sorted(res.open_ports)

    # web scraping

    async def _scrape_port(
        self, sub, port, https
    ):
        scheme = "https" if https else "http"
        url = f"{scheme}://{sub}/" if port in (80, 443) else f"{scheme}://{sub}:{port}/"

        code, body, hdrs, err = await self._aget(url, to=self.cfg.http_to, max_b=65536)

        if code == 0:
            if err and self.cfg.verbose > 0:
                self._v(f"scrape  {url}  ->  {err[:80]}")
            return 0, "", "", []

        # extract <title>
        title = ""
        try:
            parser = _TitleParser()
            parser.feed(body[:16384].decode("utf-8", errors="replace"))
            title = " ".join(parser.title.split()).strip()
        except Exception:
            pass

        hl = {k.lower(): v for k, v in hdrs.items()}
        server = hl.get("server", "")

        # tech detection: headers first, then body patterns
        tech = []
        for hdr_name in ("x-powered-by", "x-generator", "x-cms", "x-drupal-cache"):
            val = hl.get(hdr_name, "")
            if val and val not in tech:
                tech.append(val)

        snip = body[:8192].decode("utf-8", errors="replace").lower()
        patterns = {
            "WordPress": r"wp-content|wp-includes",
            "Drupal": r"drupal\.js|drupal\.settings",
            "Joomla": r"/components/com_",
            "Laravel": r"laravel_session",
            "Django": r"csrfmiddlewaretoken",
            "React": r"react\.development|react-dom",
            "Angular": r"ng-version|angular\.js",
            "Vue": r"vue\.js|__vue__",
            "Bootstrap": r"bootstrap\.min\.css|bootstrap\.bundle",
            "jQuery": r"jquery\.min\.js|jquery-",
            "Next.js": r"__next|_next/static",
            "Nuxt": r"__nuxt|_nuxt/",
            "Cloudflare": r"cloudflare",
        }
        for name, pat in patterns.items():
            if re.search(pat, snip) and name not in tech:
                tech.append(name)

        if self.cfg.verbose > 0:
            bits = [f"scrape  {url}", f"code={code}"]
            if title:
                bits.append(f"title={title[:50]}")
            if server:
                bits.append(f"server={server[:32]}")
            self._v("  ".join(bits))

        return code, title, server, tech

    """
    try all open ports on a subdomain, prefer https before http
    stops at first port that returns a usable status code
    """

    async def _scrape(
        self, sub, open_ports
    ):
        if not self.cfg.scrape_on or not open_ports:
            return 0, "", "", []

        priority = sorted(open_ports, key=lambda p: (p not in (443, 8443, 4443), p))

        for port in priority:
            https = port in (443, 8443, 4443)
            code, title, server, tech = await self._scrape_port(sub, port, https)
            if code > 0:
                return code, title, server, tech

        return 0, "", "", []

    # per-subdomain workflow

    async def _process_sub(
        self,
        sub,
        sources,
        prog,
        tid,
        live,
        live_subs,
    ):
        t0 = time.perf_counter()

        ip = await self._resolve(sub)

        if ip:
            open_ports = await self._scan_web(sub, ip)
            code, title, server, tech = await self._scrape(sub, open_ports)
            sub_err = (
                "scrape failed"
                if self.cfg.scrape_on and open_ports and code == 0
                else None
            )
        else:
            open_ports = []
            code, title, server, tech = 0, "", "", []
            sub_err = "no dns"

        info = SubHit(
            subdomain=sub,
            ip=ip,
            sources=sources,
            ports=open_ports,
            status=code,
            title=title,
            server=server,
            tech=tech,
            elapsed=round(time.perf_counter() - t0, 3),
            err=sub_err,
        )

        async with self._lock:
            live_subs.append(info)

        prog.advance(tid)
        live.update(build_live_panel(prog, live_subs, self.cfg.domain))

        return info

    # main entry point

    async def run(self):
        started = datetime.now(timezone.utc)
        t0 = time.perf_counter()
        domain = self.cfg.domain

        # phase 1: passive enumeration
        #
        # all sources fire simultaneously, results merged into sub -> [sources]
        # per-source counts printed immediately so you can see what's working
        #

        if not self.cfg.quiet:
            console.print()
            hr("Passive Enumeration")
            console.print()

        source_coros = [
            self._src_crtsh(domain),
            self._src_hackertarget(domain),
            self._src_alienvault(domain),
            self._src_urlscan(domain),
            self._src_rapiddns(domain),
        ]
        src_names = ["crt.sh", "hackertarget", "alienvault", "urlscan", "rapiddns"]

        if self.cfg.shodan_key:
            source_coros.insert(0, self._src_shodan(domain, self.cfg.shodan_key))
            src_names.insert(0, "shodan")

        # all sources in parallel
        batch = await asyncio.gather(*source_coros, return_exceptions=True)

        # merge + print per-source result counts
        sub_sources = {}
        if not self.cfg.quiet:
            console.print()

        for name, result in zip(src_names, batch):
            if isinstance(result, Exception):
                self._err(f"{name}: unhandled exception, {result}")
                if not self.cfg.quiet:
                    console.print(
                        Text.assemble(
                            ("  ✗ ", RED),
                            (f"{name:<16}", WHITE),
                            ("  error", DIM),
                        )
                    )
                continue

            count = 0
            for sub, src in result:
                sub = sub.strip().lower()
                if not sub:
                    continue
                self._total_raw += 1
                count += 1
                if sub not in sub_sources:
                    sub_sources[sub] = []
                if src not in sub_sources[sub]:
                    sub_sources[sub].append(src)

            color = GREEN if count else DIMMER
            count_label = f"{count} results" if count else "0 results"
            if not self.cfg.quiet:
                console.print(
                    Text.assemble(
                        ("  ◉ " if count else "  ○ ", color),
                        (f"{name:<16}", WHITE),
                        ("  →  ", DIM),
                        (count_label, CYAN if count else DIM),
                    )
                )

        self._found = set(sub_sources.keys())
        dedup_count = len(self._found)

        if not self.cfg.quiet:
            console.print()
            console.print(
                Text.assemble(
                    ("  total unique subdomains: ", DIM),
                    (str(dedup_count), f"bold {WHITE}"),
                )
            )
            console.print()

        # surface source errors right after enumeration
        if self._errors and not self.cfg.quiet:
            for e in self._errors:
                console.print(Text(f"  WARN  {e}", style=YELLOW))
            console.print()
            self._errors.clear()

        # phase 2: brute force (optional)
        if self.cfg.brute:
            if not self.cfg.quiet:
                hr("Brute Force")
                console.print()

            words = list(WORDLIST)
            if self.cfg.wordlist and self.cfg.wordlist.exists():
                extra = self.cfg.wordlist.read_text(
                    encoding="utf-8", errors="ignore"
                ).splitlines()
                words = list(set(words + [w.strip() for w in extra if w.strip()]))

            if not self.cfg.quiet:
                console.print(
                    Text(f"  → trying {len(words):,} words against {domain}", style=DIM)
                )
            brute_results = await self._src_brute(domain, words)

            for sub, src in brute_results:
                self._total_raw += 1
                if sub not in sub_sources:
                    sub_sources[sub] = []
                if src not in sub_sources[sub]:
                    sub_sources[sub].append(src)

            self._found = set(sub_sources.keys())
            if not self.cfg.quiet:
                console.print(
                    Text(
                        f"  → found {len(brute_results)} new subdomains via brute force",
                        style=DIM,
                    )
                )
                console.print()

        subs_list = sorted(sub_sources.keys())

        if not subs_list:
            return SubRun(
                domain=domain,
                subdomains=[],
                total_found=dedup_count,
                total_resolved=0,
                started=started.isoformat(),
                finished=datetime.now(timezone.utc).isoformat(),
                elapsed=round(time.perf_counter() - t0, 3),
                errors=self._errors,
            )

        # phase 3: parallel resolve + port scan + scrape
        #
        # each subdomain: resolve dns -> port scan + scrape in parallel
        # _resolve_sem and _nmap_sem prevent thundering-herd

        if not self.cfg.quiet:
            hr("Resolve  ·  Port Scan  ·  Scrape")
            console.print()

        live_subs = []
        prog = mk_prog(transient=False)
        tid = prog.add_task(
            f"Processing {len(subs_list)} subdomains", total=len(subs_list)
        )

        live_console = console
        if self.cfg.quiet:
            live_console = Console(
                file=io.StringIO(),
                highlight=False,
                force_terminal=False,
                color_system=None,
            )

        live = Live(
            build_live_panel(prog, live_subs, domain),
            console=live_console,
            refresh_per_second=8,
            transient=True,
        )

        all_results = []

        async def _run_one(sub):
            info = await self._process_sub(
                sub, sub_sources[sub], prog, tid, live, live_subs
            )
            all_results.append(info)
            ip_part = info.ip or "unresolved"
            src_part = ", ".join(info.sources[:2])
            if not self.cfg.quiet:
                live.console.print(
                    Text.assemble(
                        ("  ◉ ", GREEN),
                        (f"{sub:<46}", f"bold {WHITE}"),
                        ("  →  ", DIM),
                        (ip_part, SVC_COL),
                        ("  ", DIM),
                        (f"[{src_part}]", DIMMER),
                    )
                )
            if self.cfg.verbose > 0 and not self.cfg.quiet:
                live.console.print(
                    Text(
                        f"      ports={','.join(str(p) for p in info.ports) or '-'}  "
                        f"status={info.status or '-'}  "
                        f"title={(info.title or '-')[:60]}",
                        style=DIMMER,
                    )
                )

        live.start()
        try:
            await asyncio.gather(*[asyncio.create_task(_run_one(s)) for s in subs_list])
        finally:
            live.stop()

        all_results.sort(key=lambda x: x.subdomain)
        resolved = sum(1 for r in all_results if r.ip)

        return SubRun(
            domain=domain,
            subdomains=all_results,
            total_found=len(all_results),
            total_resolved=resolved,
            started=started.isoformat(),
            finished=datetime.now(timezone.utc).isoformat(),
            elapsed=round(time.perf_counter() - t0, 3),
            errors=self._errors,
        )


def run_cli(argv = None, prog = None):
    parser = build_parser(prog=prog)
    args = parser.parse_args(argv)

    # strip scheme if you typed a full url
    domain = re.sub(r"^https?://", "", args.domain.strip().lower()).split("/")[0]

    if not domain:
        console.print(Text("  ERROR  No domain specified.", style=RED))
        return 2
    if args.quiet and args.v:
        console.print(Text("  ERROR  Choose either -v or -q, not both.", style=RED))
        return 2

    if args.resolve_concurrency < 1 or args.nmap_concurrency < 1:
        console.print(Text("  ERROR  Concurrency values must be >= 1.", style=RED))
        return 2

    cfg = Cfg(
        domain=domain,
        shodan_key=args.shodan_key,
        brute=args.brute,
        wordlist=args.wordlist,
        nmap_on=not args.no_nmap,
        scrape_on=not args.no_scrape,
        resolve_c=args.resolve_concurrency,
        nmap_c=args.nmap_concurrency,
        http_to=args.http_timeout,
        debug=args.debug,
        verbose=args.v,
        quiet=args.quiet,
    )

    if not args.quiet:
        hdr(domain, cfg)
    scanner = SubScanner(cfg)

    try:
        run = asyncio.run(scanner.run())
    except KeyboardInterrupt:
        console.print()
        console.print(Text("  Interrupted.", style=YELLOW))
        return 130
    except Exception as err:
        t = Text()
        t.append("  ERROR  ", style=f"bold {RED}")
        t.append(str(err), style=DIM)
        console.print(t)
        if args.debug:
            console.print(Text(traceback.format_exc(), style=DIMMER))
        return 1
    finally:
        scanner.close()

    show_run(run)

    if run.errors:
        hr("Source Errors")
        console.print()
        for e in run.errors:
            console.print(Text(f"  {e}", style=DIMMER))
        console.print()

    if args.out:
        out_path, mode = _out_mode(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if mode == "json":
            out_path.write_text(
                json.dumps(run.to_dict(), indent=2), encoding="utf-8"
            )
        elif mode == "csv":
            out_path.write_text(_sub_csv(run), encoding="utf-8")
        else:
            out_path.write_text(build_sub_html(run), encoding="utf-8")
        if args.v:
            console.print(Text(f"  output mode  {mode}  ->  {out_path}", style=DIMMER))
        t = Text()
        t.append("  Report saved  ", style=DIM)
        t.append(str(out_path), style=CYAN)
        console.print(t)
        console.print()

    return 0


# compatibility aliases
res_tbl = sub_tbl
stats_tbl = sum_tbl
show = show_run
_csv_sub = _sub_csv
build_html = build_sub_html
mk_parser = build_parser


def main():
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()


__all__ = [
    "Cfg",
    "SubCfg",
    "SubHit",
    "SubInfo",
    "SubRun",
    "SubScanOut",
    "SubScanner",
    "build_live_panel",
    "build_parser",
    "build_sub_html",
    "live_disc_tbl",
    "run_cli",
]
