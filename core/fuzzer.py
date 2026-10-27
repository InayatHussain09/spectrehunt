"""
SpectreHunt :: core/fuzzer.py
Prioritised fuzzing engine: query params, POST, JSON bodies, path segments,
marker validation, timing-based blind RCE, rate-limit backoff, diagnostics.

Author : Inayat Hussain
"""

from __future__ import annotations

import base64
import binascii
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import quote

import requests

from config import (
    API_HINTS, DEFAULT_MAX_BRUTE_PARAMS, DEFAULT_MAX_JOBS, DEFAULT_RATE_LIMIT,
    DEFAULT_THREADS, DEFAULT_TIMEOUT, DEFAULT_TIMING_DELAY, HIGH_VALUE_PARAMS,
    MARKERS, SEVERITY, TIMING_PAYLOADS, log,
)
from payloads.default import HIDDEN_PARAMS, build_payloads, build_probes
from utils.parser import set_param

WS_RE = re.compile(r"\s+")
HIGH_VALUE_SET = {p.lower() for p in HIGH_VALUE_PARAMS}
SEG_PARAM = "__seg__"


@dataclass
class Finding:
    vtype: str
    url: str
    param: str
    method: str
    payload: str
    evidence: str
    severity: str = field(default="HIGH")

    @property
    def prefix(self) -> str:
        return {"lfi": "[LFI]", "rfi": "[RFI]", "rce": "[RCE]",
                "traversal": "[TRAV]"}.get(self.vtype, "[?]")


def _try_base64(text: str):
    if not text:
        return None
    compact = "".join(text.split())
    if len(compact) < 16:
        return None
    try:
        raw = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
    return decoded if printable / max(len(decoded), 1) > 0.85 else None


def _evidence(body: str, marker: str, width: int = 90) -> str:
    idx = body.lower().find(marker.lower())
    if idx < 0:
        return ""
    return WS_RE.sub(" ", body[max(0, idx - 30): idx + width]).strip()


def fill_segment(template: str, payload: str) -> str:
    if "%" in payload:
        value = payload
    else:
        value = quote(payload, safe="/\\:;?&=+$@,~")
    return template.replace("{SEG}", value)


def looks_like_api(url: str) -> bool:
    low = url.lower()
    return any(hint in low for hint in API_HINTS)


class Fuzzer:
    def __init__(
        self,
        session: requests.Session,
        timeout: int = DEFAULT_TIMEOUT,
        waf_bypasser=None,
        callback: str | None = None,
        threads: int = DEFAULT_THREADS,
        stack: str = "generic",
        os_family: str = "linux",
        base_url: str = "",
        max_jobs: int = DEFAULT_MAX_JOBS,
        max_brute_params: int = DEFAULT_MAX_BRUTE_PARAMS,
        timing: bool = True,
        timing_delay: int = DEFAULT_TIMING_DELAY,
        json_mode: bool = True,
        rate_limit: float = DEFAULT_RATE_LIMIT,
    ):
        self.session = session
        self.timeout = timeout
        self.bypasser = waf_bypasser
        self.callback = callback
        self.threads = max(1, threads)
        self.stack = stack
        self.os_family = os_family
        self.base_url = base_url
        self.max_jobs = max_jobs
        self.max_brute_params = max_brute_params
        self.timing = timing
        self.timing_delay = timing_delay
        self.json_mode = json_mode
        self.rate_limit = rate_limit

        self.payloads = build_payloads(stack, os_family)
        self.probes = build_probes(self.payloads)

        self.findings: list = []
        self._baselines: dict = {}
        self._lock = threading.Lock()
        self.requests_sent = 0
        self._block_until = 0.0
        self._backoff = 0.0
        self.stats = {"jobs": 0, "params": 0, "brute_params": 0,
                      "segments": 0, "json": 0, "endpoints": 0}

    def _gate(self) -> None:
        if self.rate_limit:
            time.sleep(self.rate_limit)
        while True:
            with self._lock:
                wait = self._block_until - time.time()
            if wait <= 0:
                return
            time.sleep(min(wait, 2.0))

    def _back_off(self) -> None:
        with self._lock:
            self._backoff = min(self._backoff * 2 if self._backoff else 2.0, 30.0)
            self._block_until = time.time() + self._backoff
            delay = self._backoff
        log("[!]", f"rate limited -- backing off {delay:.0f}s")

    def _send(self, url: str, param: str, value: str, method: str):
        if method == "JSON":
            return self.session.post(url, json={param: value},
                                     timeout=self.timeout, allow_redirects=True)
        if method == "POST":
            return self.session.post(url, data={param: value},
                                     timeout=self.timeout, allow_redirects=True)
        if method == "SEG":
            return self.session.get(fill_segment(url, value),
                                    timeout=self.timeout, allow_redirects=True)
        return self.session.get(set_param(url, param, value),
                                timeout=self.timeout, allow_redirects=True)

    def request_timed(self, url: str, param: str, value: str, method: str = "GET"):
        for attempt in range(2):
            self._gate()
            started = time.time()
            try:
                resp = self._send(url, param, value, method)
            except requests.RequestException:
                return None, 0.0
            elapsed = time.time() - started
            with self._lock:
                self.requests_sent += 1
                if resp.status_code not in (429, 503):
                    self._backoff = 0.0
            if resp.status_code in (429, 503) and attempt == 0:
                self._back_off()
                continue
            return resp.text, elapsed
        return None, 0.0

    def request(self, url: str, param: str, value: str, method: str = "GET"):
        return self.request_timed(url, param, value, method)[0]

    def post_raw(self, url: str, body: str):
        try:
            resp = self.session.post(url, data=body, timeout=self.timeout)
            with self._lock:
                self.requests_sent += 1
            return resp.text
        except requests.RequestException:
            return None

    def baseline(self, url: str, param: str, method: str) -> str:
        key = (url, param, method)
        if key not in self._baselines:
            rnd = f"spectrehunt{random.randint(100000, 999999)}"
            self._baselines[key] = self.request(url, param, rnd, method) or ""
        return self._baselines[key]

    def _validate(self, payload: str, body, vtype: str, baseline: str):
        if not body:
            return False, ""
        if "php://filter" in payload and "base64" in payload:
            decoded = _try_base64(body)
            if decoded:
                body = decoded
        low_body, low_base = body.lower(), (baseline or "").lower()
        for marker in MARKERS.get(vtype, []):
            m = marker.lower()
            if m in low_body and m not in low_base:
                return True, _evidence(body, marker)
        return False, ""

    def _candidates(self, vtype: str, probe_only: bool) -> list:
        source = self.probes.get(vtype, []) if probe_only else self.payloads.get(vtype, [])
        cb = self.callback or "127.0.0.1:8899"
        payloads = [p.replace("{cb}", cb) for p in source]
        if self.bypasser is None:
            return payloads
        expanded: list = []
        for p in payloads:
            expanded.append(p)
            for variant in self.bypasser.mutate(p):
                expanded.append(variant.replace("{cb}", cb))
        return expanded

    def _timing_test(self, url: str, param: str, method: str):
        family = "windows" if self.os_family == "windows" else "unix"
        _, t0 = self.request_timed(url, param, "spectrehunt_timing", method)
        _, t1 = self.request_timed(url, param, "spectrehunt_timing", method)
        samples = [t for t in (t0, t1) if t]
        base = min(samples) if samples else 0.0
        if base <= 0:
            return False, ""
        for raw, delay in TIMING_PAYLOADS[family]:
            payload = raw.format(d=self.timing_delay, n=self.timing_delay + 1)
            _, elapsed = self.request_timed(url, param, payload, method)
            if elapsed and elapsed >= base + delay - 0.6:
                return True, f"{payload} -> {elapsed:.2f}s vs baseline {base:.2f}s"
        return False, ""

    @staticmethod
    def _priority(url: str, param: str, real_params: set, method: str) -> int:
        score = 0
        if param == SEG_PARAM:
            score += 80
        if param in real_params:
            score += 100
        if param.lower() in HIGH_VALUE_SET:
            score += 50
        if method == "JSON":
            score -= 10
        score += max(0, 25 - url.count("/"))
        return score

    def _build_jobs(self, targets: dict, segment_targets: list, types: list,
                    brute_params: bool):
        raw = []
        for url, meta in targets.items():
            method = meta.get("method", "GET")
            real = set(meta.get("params", {}).keys())
            params = list(real)
            if not params and brute_params:
                params = HIDDEN_PARAMS[: self.max_brute_params]
                self.stats["brute_params"] += 1
            self.stats["params"] += len(params)
            probe_only = not real
            for param in params:
                for vtype in types:
                    raw.append((self._priority(url, param, real, method),
                                url, param, method, vtype, probe_only))
                    if self.json_mode and looks_like_api(url):
                        raw.append((self._priority(url, param, real, "JSON"),
                                    url, param, "JSON", vtype, probe_only))
                        self.stats["json"] += 1

        for seg in segment_targets:
            self.stats["segments"] += 1
            for vtype in types:
                raw.append((self._priority(seg["template"], SEG_PARAM, set(), "SEG"),
                            seg["template"], SEG_PARAM, "SEG", vtype, False))

        self.stats["endpoints"] = len(targets)
        raw.sort(key=lambda j: -j[0])
        if self.max_jobs and len(raw) > self.max_jobs:
            log("[*]", f"job queue capped: {len(raw)} -> {self.max_jobs}")
            raw = raw[: self.max_jobs]
        self.stats["jobs"] = len(raw)
        return [(u, p, m, t, po) for _s, u, p, m, t, po in raw]

    def _worker(self, job: tuple) -> None:
        url, param, method, vtype, probe_only = job
        baseline = self.baseline(url, param, method)
        for payload in self._candidates(vtype, probe_only):
            body = self.request(url, param, payload, method)
            hit, evidence = self._validate(payload, body, vtype, baseline)
            if hit:
                with self._lock:
                    self.findings.append(Finding(
                        vtype=vtype, url=url, param=param, method=method,
                        payload=payload, evidence=evidence, severity=SEVERITY[vtype]))
                return
        if vtype == "rce" and self.timing:
            hit, evidence = self._timing_test(url, param, method)
            if hit:
                with self._lock:
                    self.findings.append(Finding(
                        vtype="rce", url=url, param=param, method=method,
                        payload="(timing-based)", evidence=evidence, severity="HIGH"))

    def diagnose(self, targets: dict) -> list:
        lines = []
        with_params = sum(1 for v in targets.values() if v["params"])
        lines.append(f"endpoints mapped          : {len(targets)}")
        lines.append(f"endpoints with parameters : {with_params}")
        lines.append(f"parameters fuzzed         : {self.stats['params']}")
        lines.append(f"path-segment params       : {self.stats['segments']}")
        lines.append(f"json body variants        : {self.stats['json']}")
        lines.append(f"jobs executed             : {self.stats['jobs']}")
        lines.append(f"requests sent             : {self.requests_sent}")
        if not self.findings:
            if self.stats["params"] == 0:
                lines.append("verdict: no parameters anywhere -- route-based site. "
                             "Try --no-crawl with a hand-built URL list.")
            elif self.requests_sent < 50:
                lines.append("verdict: few requests landed -- check rate limiting "
                             "or add --rate-limit 0.5")
            else:
                lines.append("verdict: parameters were genuinely fuzzed and clean. "
                             "Try --max-jobs 0 or --stack generic.")
        return lines

    def scan(self, targets: dict, types: list, brute_params: bool = True,
             segment_targets: list | None = None) -> list:
        segment_targets = segment_targets or []
        log("[*]", f"stack {self.stack}/{self.os_family} "
                   f"({', '.join(f'{k}={len(v)}' for k, v in self.payloads.items())})")
        jobs = self._build_jobs(targets, segment_targets, types, brute_params)
        if not jobs:
            log("[!]", "no parameters to fuzz")
            return []
        log("[*]", f"fuzzing {len(jobs)} jobs / {self.threads} threads"
                   + (" + timing" if self.timing else ""))
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            list(pool.map(self._worker, jobs))
        return self.findings
