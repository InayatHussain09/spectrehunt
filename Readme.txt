bash
cat > README.md <<'MDEOF'
<div align="center">
/ __| _ | / | | _ | __| | | | \ | | |
_ | |) | || | | | | |) | | | || | | | | |
) | /| || | | | | _ <| || _ | |\ | | |
|__/|| |___| || || ____|| ||| _| ||

**File Inclusion & Command Execution Framework**

`LFI · RFI · RCE · PATH TRAVERSAL · COMMAND INJECTION`

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-5.1.0-orange.svg)]()

**Author:** Inayat Hussain — Red Team Operator | Offensive Security Researcher

</div>

---

## What it is

A CLI vulnerability hunter and exploit chainer for exactly **five** bug classes. Narrow scope by design — one tool that is genuinely good at one family of bugs instead of mediocre at everything.

It maps a target, fuzzes every parameter it can find, and when it finds a file-inclusion bug it **escalates it to code execution** and lands on the box.

## Features

**Discovery — fully automatic**
- Concurrent same-host BFS crawler (depth + URL capped)
- `robots.txt`, `sitemap.xml` (with sitemap-index recursion), 80 common-path probes
- Parameter harvesting from query strings, HTML forms and URL path segments
- URL harvesting from inline scripts, JS bundles and JSON responses
- Hidden-parameter brute force on parameterless endpoints
- Adaptive Playwright rendering, only when the page is an empty SPA shell

**Fingerprinting**
- Stack detection: PHP, ASP.NET, Java, Node, Python — weighted evidence, ambiguity guard
- OS detection (drives Linux vs Windows payload ladders)
- CMS detection: WordPress, Drupal, Joomla
- WAF detection across 11 vendors
- Edge challenge detection (Cloudflare)
- CVE correlation

**Fuzzing**
- 80+ built-in payloads with stack-aware selection
- WAF mutation engine — 6 signature-breaking variants per payload
- Baseline-diff validation for near-zero false positives
- Priority job queue with hard cap
- JSON body fuzzing on API paths, path-segment fuzzing
- Timing-based blind RCE
- Rate-limit backoff

**Escalation — executed, not hinted**

Runs cheapest-first and reports every step honestly:

1. `php://filter` source disclosure + credential grep
2. `data://` code execution
3. `php://input` code execution
4. `php://filter` chain RCE — arbitrary code exec, **zero file writes**
5. Log / `/proc/self/environ` / session-file poisoning
6. Webshell deploy **with HTTP verification**
7. Reverse-shell sequence against a live listener
8. Automated post-exploitation enumeration

## Install

```bash
git clone https://github.com/<your-username>/spectrehunt.git
cd spectrehunt
pip install -r requirements.txt

# optional: installs the `spectrehunt` command
pip install -e . --break-system-packages

# optional: SPA rendering
pip install playwright && python3 -m playwright install chromium
Usage
bash
# recon + fuzz
spectrehunt https://target.com --depth 3 --max-jobs 800

# fast targeted pass
spectrehunt https://target.com -t traversal rce --depth 2

# authenticated
spectrehunt https://target.com -C 'PHPSESSID=abc' --rate-limit 0.3

# hand-built URL list, no crawl
spectrehunt --list urls.txt --no-crawl -t traversal rce

# full escalation
spectrehunt https://target.com -t lfi --filter-chain --poison
spectrehunt https://target.com -t rce --deploy-webshell --shell --loot
Local lab
bash
php -d display_errors=On -d allow_url_include=On -S 0.0.0.0:8000 -t spectrelab
spectrehunt http://127.0.0.1:8000 --depth 3
spectrelab/ is a purpose-built vulnerable PHP app with four deliberate sinks:
?page= (include), ?file= (readfile), ?cmd= (system), ?remote= (remote include).

How it works
fingerprint -> discovery -> crawl -> prioritised fuzz -> validate -> chain -> escalate
Every fetch failure is logged with its exception class. A clean run proves itself with a
diagnostics block: endpoints mapped, jobs executed, requests sent, verdict.

Scope & limitations
Target	Odds of a finding
Legacy PHP / CMS / admin panels	40–60%
Government & university portals	20–35%
Modern framework apps, query-string routing	10–20%
SPAs with JSON API	5–15%
Detection is marker-based with a baseline diff — it confirms a bug when the response
contains a known string. Blind LFI with swallowed output reads as clean; blind RCE is
caught via timing.

Works on: classic .php / .aspx / .jsp apps, CMS installs, sites behind a WAF.
Struggles with: SPAs (use --render on), JSON APIs, Cloudflare-normalised path traversal.
Never: client-side routing (/#/page), WebSockets.

Not a general scanner — no SQLi, XSS or SSRF by design.

Project structure
spectrehunt/
├── main.py                 CLI + orchestration
├── config.py               constants, palette, WAF sigs, payload tables
├── core/
│   ├── crawler.py          concurrent BFS + discovery seeding
│   ├── discovery.py        robots/sitemap/common-path/JS harvesting
│   ├── fingerprinter.py    stack, OS, CMS, WAF, CVE
│   ├── fuzzer.py           prioritised engine, validation, timing
│   ├── waf_bypasser.py     payload mutation
│   ├── chain.py            escalation orchestrator
│   ├── filterchain.py      php://filter chain generator
│   ├── poison.py           log / environ / session poisoning
│   ├── shell.py            listener, webshell deploy, loot
│   ├── renderer.py         optional Playwright
│   ├── encoder.py          encoding primitives
│   └── ui.py               presentation layer
├── payloads/default.py     80+ stack-aware payloads
├── utils/
│   ├── parser.py           HTML parsing
│   └── callback.py         RFI proof server
└── spectrelab/             vulnerable test target
License
MIT — see LICENSE.

Author
Inayat Hussain — Red Team Operator | Offensive Security Researcher
