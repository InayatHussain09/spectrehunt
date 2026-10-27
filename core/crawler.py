"""
SpectreHunt :: core/crawler.py
Concurrent same-host BFS crawler + discovery seeding + adaptive rendering.

Author : Inayat Hussain
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit, urlunsplit

import requests

from config import (
    DEFAULT_DEPTH, DEFAULT_HEADERS, DEFAULT_MAX_URLS, DEFAULT_TIMEOUT,
    PATH_SEGMENT_BLOCKLIST, PATH_SEGMENT_EXT, log,
)
from core.discovery import Discovery
from utils.parser import (
    extract_forms, extract_links, extract_query_params, same_host, strip_fragment,
)

STATIC_EXT = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".mp3",
)
BINARY_CTYPE = ("image/", "font/", "video/", "audio/", "octet-stream", "css")
JS_MARKERS = ('id="root"', "id='root'", 'id="app"', "id='app'",
              "__next_data__", "ng-app", "data-reactroot", "data-v-app")
SEG_PLACEHOLDER = "{SEG}"


class _Page:
    __slots__ = ("text", "url", "headers", "status_code")

    def __init__(self, text, url, headers=None, status_code=200):
        self.text = text
        self.url = url
        self.headers = headers or {"Content-Type": "text/html"}
        self.status_code = status_code


class Crawler:
    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        max_depth: int = DEFAULT_DEPTH,
        max_urls: int = DEFAULT_MAX_URLS,
        timeout: int = DEFAULT_TIMEOUT,
        threads: int = 8,
        renderer=None,
        render_mode: str = "auto",
        path_segments: bool = True,
        probe: bool = True,
    ):
        self.session = session
        self.base_url = strip_fragment(base_url)
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.threads = max(1, threads)
        self.renderer = renderer
        self.render_mode = render_mode
        self.path_segments = path_segments
        self.probe = probe
        self.crawl_timeout = max(6, min(timeout, 20))
        self.targets: dict = {}
        self.segment_targets: list = []
        self.pages_crawled = 0
        self.errors: dict = {}
        self._seen_segments: set = set()
        self._err_lock = threading.Lock()
        self.use_render = render_mode == "on"
        self._auto_decided = render_mode != "auto"

    def _record(self, url: str, params: dict, method: str = "GET") -> None:
        url = strip_fragment(url)
        if not url:
            return
        entry = self.targets.setdefault(url, {"params": {}, "method": method})
        for key, value in params.items():
            entry["params"].setdefault(key, value)

    def _note_error(self, url: str, exc: Exception) -> None:
        reason = f"{exc.__class__.__name__}: {exc}"
        with self._err_lock:
            count = self.errors.get(reason, 0) + 1
            self.errors[reason] = count
            first = count == 1
        if first:
            log("[X]", f"fetch failed {url} -- {reason}")

    def _is_value_segment(self, segment: str) -> bool:
        if not segment or len(segment) > 60:
            return False
        if segment.isdigit():
            return True
        if "." in segment:
            return segment.rsplit(".", 1)[-1].lower() in PATH_SEGMENT_EXT
        return segment.lower() not in PATH_SEGMENT_BLOCKLIST

    def _harvest_segments(self, url: str) -> None:
        if not self.path_segments:
            return
        parts = urlsplit(url)
        segments = [s for s in parts.path.split("/") if s]
        if not segments:
            return
        last = segments[-1]
        if not self._is_value_segment(last):
            return
        template = urlunsplit((
            parts.scheme, parts.netloc,
            "/" + "/".join(segments[:-1] + [SEG_PLACEHOLDER]),
            parts.query, "",
        ))
        key = (template, last)
        if key in self._seen_segments:
            return
        self._seen_segments.add(key)
        self.segment_targets.append({"template": template, "value": last, "url": url})

    def _fetch(self, url: str):
        if self.use_render and self.renderer is not None:
            html, final_url = self.renderer.render(url)
            if html:
                return url, _Page(html, final_url)

        last: Exception | None = None
        for attempt in range(2):
            try:
                return url, self.session.get(url, timeout=self.crawl_timeout,
                                             allow_redirects=True)
            except requests.RequestException as exc:
                last = exc
                time.sleep(0.4 * (attempt + 1))

        try:
            resp = requests.get(url, timeout=max(self.timeout, 20), verify=False,
                                headers=dict(DEFAULT_HEADERS))
            log("[*]", f"session fetch failed for {url}; standalone retry OK "
                       f"(HTTP {resp.status_code})")
            return url, resp
        except requests.RequestException as exc:
            last = exc

        if last is not None:
            self._note_error(url, last)
        return url, None

    @staticmethod
    def _looks_like_spa(html: str, link_count: int) -> bool:
        if link_count >= 5:
            return False
        low = (html or "").lower()
        return "<script" in low and any(m in low for m in JS_MARKERS)

    def crawl(self) -> dict:
        try:
            seeds = Discovery(self.session, self.base_url, timeout=self.timeout,
                              probe=self.probe, max_urls=self.max_urls).seeds()
        except Exception as exc:
            log("[X]", f"discovery failed: {exc}")
            seeds = set()

        frontier = [self.base_url]
        seen = {self.base_url}
        for seed in seeds:
            self._record(seed, extract_query_params(seed))
            self._harvest_segments(seed)
            if seed not in seen:
                seen.add(seed)
                frontier.append(seed)

        depth = 0
        while frontier and depth <= self.max_depth and len(self.targets) < self.max_urls:
            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                results = list(pool.map(self._fetch, frontier))

            next_frontier = []
            for _requested, resp in results:
                if resp is None:
                    continue
                self.pages_crawled += 1
                final_url = strip_fragment(resp.url)
                self._record(final_url, extract_query_params(final_url))
                self._harvest_segments(final_url)

                ctype = (resp.headers.get("Content-Type") or "").lower()
                if any(b in ctype for b in BINARY_CTYPE):
                    continue

                html = resp.text or ""
                forms = extract_forms(html, final_url)
                links = extract_links(html, final_url)

                for form in forms:
                    self._record(form["action"], form["params"], form["method"])

                if (self.render_mode == "auto" and not self._auto_decided
                        and self.renderer is not None):
                    self._auto_decided = True
                    if self._looks_like_spa(html, len(links)):
                        self.use_render = True
                        log("[RENDER]", "SPA shell detected -- switching to browser")

                if "javascript" in ctype or "json" in ctype:
                    links |= Discovery.harvest_from_text(html, final_url)

                for link in links:
                    if not same_host(link, self.base_url):
                        continue
                    link = strip_fragment(link)
                    self._record(link, extract_query_params(link))
                    self._harvest_segments(link)
                    if link in seen:
                        continue
                    seen.add(link)
                    if urlsplit(link).path.lower().endswith(STATIC_EXT):
                        continue
                    if len(self.targets) + len(next_frontier) >= self.max_urls:
                        continue
                    next_frontier.append(link)

            frontier = next_frontier
            if frontier:
                log("[*]", f"  depth {depth}: {self.pages_crawled} pages, "
                           f"{len(self.targets)} endpoints, "
                           f"{len(self.segment_targets)} path params")
            depth += 1

        if self.pages_crawled == 0 and self.errors:
            log("[!]", "Crawl produced nothing. Distinct failures:")
            for reason, count in self.errors.items():
                log("[X]", f"  x{count}  {reason}")

        return self.targets

    def summary(self) -> str:
        param_count = sum(len(v["params"]) for v in self.targets.values())
        with_params = sum(1 for v in self.targets.values() if v["params"])
        text = (f"{self.pages_crawled} pages | {len(self.targets)} endpoints | "
                f"{with_params} with params ({param_count}) | "
                f"{len(self.segment_targets)} path params")
        if self.errors:
            text += f" | {sum(self.errors.values())} fetch errors"
        return text
