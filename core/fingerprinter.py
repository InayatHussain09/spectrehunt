"""
SpectreHunt :: core/fingerprinter.py
Stack, CMS, WAF, OS fingerprinting + CVE correlation + challenge detection.

Author : Inayat Hussain
"""

from __future__ import annotations

import re

import requests

from config import (
    CHALLENGE_MARKERS, DEFAULT_TIMEOUT, STACK_BODY_PATTERNS, STACK_BODY_WEIGHT,
    STACK_HEADER_SIGNATURES, STACK_HEADER_WEIGHT, STACK_THRESHOLD,
    WINDOWS_SERVER_HINTS, WINDOWS_STACKS, lookup_cves, log,
)
from core.waf_bypasser import WAFBypasser

CMS_BODY_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "wp-json", "/wp-emoji", "wordpress"],
    "Drupal": ["sites/default/files", "drupal.js", "drupal.settings", "core/misc/drupal"],
    "Joomla": ["/media/jui/", "com_content", "option=com_", "joomla"],
}
CMS_PROBES = {
    "/wp-login.php": "WordPress", "/wp-json/": "WordPress",
    "/administrator/": "Joomla", "/CHANGELOG.txt": "Drupal",
    "/README.txt": "Drupal", "/core/CHANGELOG.txt": "Drupal",
}
CMS_TO_STACK = {"WordPress": "php", "Drupal": "php", "Joomla": "php"}

SERVER_SIGNATURES = {
    "Nginx": ["nginx"], "Apache": ["apache"], "IIS": ["microsoft-iis", "iis/"],
    "LiteSpeed": ["litespeed"], "Tomcat": ["tomcat", "coyote"],
    "Gunicorn": ["gunicorn"], "Werkzeug": ["werkzeug"], "Jetty": ["jetty"],
}

GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I
)
VERSION_RE = re.compile(r"([0-9]+\.[0-9]+(?:\.[0-9]+)*)")


class Fingerprinter:
    def __init__(self, session: requests.Session, timeout: int = DEFAULT_TIMEOUT):
        self.session = session
        self.timeout = timeout

    def _probe(self, url: str):
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException:
            return None

    @staticmethod
    def _extract_version(text: str, product: str):
        if not text:
            return None
        m = re.search(re.escape(product) + r"[/ ]?([0-9][0-9.]*)", text, re.I)
        return m.group(1).rstrip(".") if m else None

    @staticmethod
    def detect_stack(headers: dict, body: str, cookie_string: str) -> str:
        header_blob = " ".join(f"{k}:{v}".lower() for k, v in dict(headers).items())
        body_blob = (body or "")[:40000].lower()
        cookie_blob = (cookie_string or "").lower()
        scores: dict = {}

        def bump(stack: str, weight: int) -> None:
            scores[stack] = scores.get(stack, 0) + weight

        for stack, sigs in STACK_HEADER_SIGNATURES.items():
            for sig in sigs:
                if sig in header_blob or sig in cookie_blob:
                    bump(stack, STACK_HEADER_WEIGHT)

        for stack, patterns in STACK_BODY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body_blob):
                    bump(stack, STACK_BODY_WEIGHT)

        if not scores:
            return "generic"
        best = max(scores, key=scores.get)
        if scores[best] < STACK_THRESHOLD:
            return "generic"
        ordered = sorted(scores.values(), reverse=True)
        if len(ordered) > 1 and ordered[0] == ordered[1]:
            return "generic"
        return best

    @staticmethod
    def detect_os(stack: str, server_header: str = "", powered_by: str = "") -> str:
        blob = f"{server_header or ''} {powered_by or ''}".lower()
        if stack in WINDOWS_STACKS:
            return "windows"
        if any(hint in blob for hint in WINDOWS_SERVER_HINTS):
            return "windows"
        if "asp.net" in blob or "aspnet" in blob:
            return "windows"
        return "linux"

    def fingerprint(self, url: str) -> dict:
        info = {
            "url": url, "server": None, "server_version": None, "powered_by": None,
            "php_version": None, "cms": None, "cms_version": None, "title": None,
            "waf": [], "cves": [], "stack": "generic", "os": "linux",
            "challenge": False,
        }

        resp = self._probe(url)
        if resp is None:
            log("[!]", f"Could not reach {url}")
            return info

        headers = resp.headers
        info["server"] = headers.get("Server")
        info["powered_by"] = headers.get("X-Powered-By")
        info["php_version"] = self._extract_version(headers.get("X-Powered-By") or "", "php")

        cookie_str = "; ".join(resp.cookies.get_dict().keys())
        cookie_str += " " + "; ".join(headers.get("Set-Cookie", "").split(","))
        info["waf"] = WAFBypasser.detect(headers, cookie_str)

        body = resp.text or ""
        low_body = body.lower()
        info["challenge"] = (
            headers.get("cf-mitigated", "").lower() == "challenge"
            or any(m in low_body for m in CHALLENGE_MARKERS)
        )

        info["stack"] = self.detect_stack(headers, body, cookie_str)
        info["os"] = self.detect_os(info["stack"], info["server"], info["powered_by"])

        server_product = None
        for product, sigs in SERVER_SIGNATURES.items():
            if info["server"] and any(s in info["server"].lower() for s in sigs):
                server_product = product
                info["server_version"] = self._extract_version(info["server"], product)
                break

        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if m:
            info["title"] = " ".join(m.group(1).split())[:120]

        for cms, sigs in CMS_BODY_SIGNATURES.items():
            if any(s in low_body for s in sigs):
                info["cms"] = cms
                break

        gen = GENERATOR_RE.search(body)
        if gen:
            gen_text = gen.group(1)
            for cms in ("WordPress", "Drupal", "Joomla"):
                if cms.lower() in gen_text.lower():
                    info["cms"] = cms
                    v = VERSION_RE.search(gen_text)
                    if v:
                        info["cms_version"] = v.group(1)

        if not info["cms"]:
            for path, cms in CMS_PROBES.items():
                probe = self._probe(url.rstrip("/") + path)
                if probe is None or probe.status_code >= 400 or not probe.text:
                    continue
                if cms == "Drupal" and path == "/README.txt" and "drupal" not in probe.text.lower():
                    continue
                info["cms"] = cms
                v = VERSION_RE.search(probe.text[:4000])
                if v:
                    info["cms_version"] = info["cms_version"] or v.group(1)
                break

        if info["cms"] == "WordPress" and not info["cms_version"]:
            v = re.search(r"[?&]ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)", body)
            if v:
                info["cms_version"] = v.group(1)

        if info["stack"] == "generic" and info["cms"] in CMS_TO_STACK:
            info["stack"] = CMS_TO_STACK[info["cms"]]
        if info["server"] and "iis" in info["server"].lower():
            info["os"] = "windows"

        for product, version in (
            (info["cms"], info["cms_version"]),
            (server_product, info["server_version"]),
            ("PHP", info["php_version"]),
            ("ASP.NET" if info["stack"] == "aspnet" else None, None),
        ):
            for entry in lookup_cves(product, version):
                if entry not in info["cves"]:
                    info["cves"].append(entry)

        return info
