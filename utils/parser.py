"""
SpectreHunt :: utils/parser.py
HTML parsing helpers for crawling and parameter extraction.

Author : Inayat Hussain
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "about:")
LINK_TAGS = ("a", "area", "link", "script", "iframe", "frame", "form")
FORM_FIELDS = ("input", "textarea", "select")
SKIP_FIELDS = {"submit", "reset", "button", "image", "file"}


def strip_fragment(url: str) -> str:
    return url.split("#", 1)[0]


def same_host(a: str, b: str) -> bool:
    return urlsplit(a).netloc.lower() == urlsplit(b).netloc.lower()


def extract_links(html: str, base_url: str) -> set:
    soup = BeautifulSoup(html or "", "html.parser")
    links = set()
    for tag in soup.find_all(LINK_TAGS):
        for attr in ("href", "src", "action"):
            value = tag.get(attr)
            if not value:
                continue
            value = value.strip()
            if value.startswith(SKIP_SCHEMES) or value == "#":
                continue
            links.add(strip_fragment(urljoin(base_url, value)))
    return links


def extract_forms(html: str, base_url: str) -> list:
    soup = BeautifulSoup(html or "", "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = urljoin(base_url, (form.get("action") or "").strip() or base_url)
        method = (form.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"
        params = {}
        for field in form.find_all(FORM_FIELDS):
            name = field.get("name")
            if not name:
                continue
            if (field.get("type") or "").lower() in SKIP_FIELDS:
                continue
            params[name] = field.get("value") or "1"
        if params:
            forms.append({"action": strip_fragment(action), "method": method,
                          "params": params})
    return forms


def extract_query_params(url: str) -> dict:
    query = parse_qs(urlsplit(url).query, keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in query.items()}


def set_param(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query[param] = [value]
    flat = {k: (v[0] if isinstance(v, list) else v) for k, v in query.items()}
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(flat), ""))
