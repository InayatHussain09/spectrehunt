"""
SpectreHunt :: core/waf_bypasser.py
WAF detection and adaptive payload mutation.

Author : Inayat Hussain
"""

from __future__ import annotations

from core import encoder
from config import WAF_SIGNATURES


class WAFBypasser:
    def __init__(self, waf_name: str | None = None, max_variants: int = 6):
        self.waf = waf_name
        self.max_variants = max_variants

    @staticmethod
    def detect(headers: dict, cookie_string: str = "") -> list:
        found = []
        hl = {str(k).lower(): str(v or "").lower() for k, v in dict(headers).items()}
        ck = (cookie_string or "").lower()

        for name, sig in WAF_SIGNATURES.items():
            hit = False
            for header_name, patterns in sig.get("headers", {}).items():
                if header_name in hl:
                    if any(p == "*" or p in hl[header_name] for p in patterns):
                        hit = True
                        break
            if not hit:
                for cookie_name in sig.get("cookies", []):
                    if cookie_name in ck:
                        hit = True
                        break
            if hit:
                found.append(name)
        return found

    def mutate(self, payload: str) -> list:
        variants: list = []

        def add(candidate: str) -> None:
            if candidate and candidate != payload and candidate not in variants:
                variants.append(candidate)

        if "/" in payload or "\\" in payload:
            add(encoder.dotdot_amplify(payload))
            add(encoder.double_url_encode(payload))
            add(encoder.case_flip(payload))
            add(encoder.slash_pad(payload))
            add(encoder.dot_pad(payload))
            add(encoder.star_pad(payload))
            add(encoder.url_encode(payload))

        if payload.startswith(("php://", "PHP://")):
            add(encoder.case_flip(payload))

        if payload.startswith("data://"):
            add(payload.replace(" ", ""))

        if " " in payload:
            add(encoder.ifs_pad(payload))
            add(encoder.tab_pad(payload))

        if not payload.endswith(("%00", "?")):
            add(payload + "%00")
            add(payload + "?")

        return variants[: self.max_variants]

    def mutate_all(self, payloads: list) -> list:
        out: list = []
        for p in payloads:
            if p not in out:
                out.append(p)
            for v in self.mutate(p):
                if v not in out:
                    out.append(v)
        return out
