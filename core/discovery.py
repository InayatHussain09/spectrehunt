"""
SpectreHunt :: core/discovery.py
Static seed discovery: robots.txt, sitemap.xml, common paths, and URL
extraction from JS/JSON bodies.

Author : Inayat Hussain
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

import requests

from config import COMMON_PATHS, log

LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
DIRECTIVE_RE = re.compile(r"^(allow|disallow|sitemap)\s*:\s*(\S+)", re.I | re.M)
ABS_URL_RE = re.compile(r"""https?://[^\s"'<>()\\]+""", re.I)
REL_URL_RE = re.compile(r"""["'(](/[A-Za-z0-9_\-./?=&%~+]+)["')]""")
QUOTED_URL_RE = re.compile(r"""["']((?:[A-Za-z0-9_\-./?=&%~+]|%[0-9a-fA-F]{2})+)["']""")

INTERESTING_EXT = (".php", ".aspx", ".asp", ".ashx", ".jsp", ".do", ".action",
                   ".html", ".htm", ".json", ".xml", ".cgi", ".pl", ".py")

MAX_SITEMAP_CHILDREN = 3


class Discovery:
    def __init__(self, session: requests.Session, base_url: str,
                 timeout: int = 15, probe: bool = True, max_urls: int = 250):
        self.session = session
        self.base_url = base_url.rstrip("/")
        self.root = "{0.scheme}://{0.netloc}".format(urlsplit(base_url))
        self.timeout = timeout
        self.probe = probe
        self.max_urls = max_urls
        self.hits: dict = {"robots": 0, "sitemap": 0, "probe": 0}

    def _get(self, url: str):
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    @staticmethod
    def _interesting(url: str) -> bool:
        path = urlsplit(url).path.lower()
        return any(path.endswith(e) for e in INTERESTING_EXT) or "?" in url

    def _robots(self) -> set:
        urls: set = set()
        resp = self._get(self.root + "/robots.txt")
        if resp is None or resp.status_code >= 400:
            return urls
        if "html" in (resp.headers.get("Content-Type") or ""):
            return urls
        for kind, value in DIRECTIVE_RE.findall(resp.text):
            kind = kind.lower()
            if kind == "sitemap":
                urls |= self._sitemap(urljoin(self.root, value))
                continue
            if value in ("/", "") or "*" in value or value.endswith("/$"):
                continue
            urls.add(urljoin(self.root, value))
        if urls:
            log("[DISC]", f"robots.txt -> {len(urls)} path(s)")
            self.hits["robots"] = len(urls)
        return urls

    def _sitemap(self, url: str | None = None, depth: int = 0) -> set:
        urls: set = set()
        if depth > 1:
            return urls
        url = url or (self.root + "/sitemap.xml")
        resp = self._get(url)
        if resp is None or resp.status_code >= 400:
            return urls
        body = resp.text or ""
        locs = LOC_RE.findall(body)
        if not locs:
            return urls
        if "<sitemapindex" in body.lower():
            for child in locs[:MAX_SITEMAP_CHILDREN]:
                urls |= self._sitemap(child, depth + 1)
        else:
            urls |= set(locs)
        if urls:
            log("[DISC]", f"sitemap -> {len(urls)} URL(s)")
            self.hits["sitemap"] = max(self.hits["sitemap"], len(urls))
        return urls

    def _common_paths(self) -> set:
        urls: set = set()
        for path in COMMON_PATHS:
            if len(urls) >= self.max_urls // 2:
                break
            resp = self._get(self.root + path)
            if resp is None or resp.status_code >= 400:
                continue
            if resp.status_code in (401, 403):
                urls.add(self.root + path)
                continue
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if any(b in ctype for b in ("image/", "font/", "video/", "audio/")):
                continue
            if len(resp.content) < 40:
                continue
            urls.add(self.root + path)
        if urls:
            log("[DISC]", f"common paths -> {len(urls)} live path(s)")
            self.hits["probe"] = len(urls)
        return urls

    @staticmethod
    def harvest_from_text(text: str, base_url: str) -> set:
        found: set = set()
        if not text:
            return found
        blob = text[:400000]
        for match in ABS_URL_RE.findall(blob):
            found.add(match.rstrip("\\,;"))
        for match in REL_URL_RE.findall(blob):
            found.add(urljoin(base_url, match))
        for match in QUOTED_URL_RE.findall(blob):
            if any(match.endswith(e) for e in INTERESTING_EXT):
                found.add(urljoin(base_url, match))
        return found

    def seeds(self) -> set:
        urls: set = set()
        try:
            urls |= self._robots()
        except Exception as exc:
            log("[X]", f"robots discovery failed: {exc}")
        try:
            urls |= self._sitemap()
        except Exception as exc:
            log("[X]", f"sitemap discovery failed: {exc}")
        if self.probe:
            try:
                urls |= self._common_paths()
            except Exception as exc:
                log("[X]", f"common-path probe failed: {exc}")

        host = urlsplit(self.base_url).netloc
        return {u.split("#", 1)[0] for u in urls
                if urlsplit(u).netloc == host}
