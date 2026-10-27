"""
SpectreHunt :: core/encoder.py
Payload mutation primitives. WAFs match signatures, not semantics.

Author : Inayat Hussain
"""

from __future__ import annotations

import base64
import random
from urllib.parse import quote


def url_encode(value: str) -> str:
    return quote(value, safe="")


def double_url_encode(value: str) -> str:
    return quote(quote(value, safe=""), safe="")


def base64_encode(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


def html_entity_encode(value: str) -> str:
    return "".join(f"&#{ord(ch)};" for ch in value)


def case_flip(value: str) -> str:
    rnd = random.Random()
    return "".join(
        (ch.upper() if rnd.random() > 0.5 else ch.lower()) if ch.isalpha() else ch
        for ch in value
    )


def slash_pad(value: str) -> str:
    return value.replace("/", "//")


def dot_pad(value: str) -> str:
    return value.replace("/", "/./")


def star_pad(value: str) -> str:
    return value.replace("/", "/**/")


def dotdot_amplify(value: str) -> str:
    return value.replace("../", "....//")


def ifs_pad(value: str) -> str:
    return value.replace(" ", "${IFS}")


def tab_pad(value: str) -> str:
    return value.replace(" ", "%09")
