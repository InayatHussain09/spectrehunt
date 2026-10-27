"""
SpectreHunt :: core/ui.py
Presentation layer. All console formatting lives here so engine modules stay
free of escape codes.

Design: violet accent, dim-grey structure, colour reserved for meaning.

Author : Inayat Hussain
"""

from __future__ import annotations

from config import C, paint

WIDTH = 68


def _fit(text, width: int) -> str:
    text = str(text)
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."


def blank() -> None:
    print()


def rule(width: int = WIDTH) -> None:
    print(paint("─" * width, C.DIM))


def title() -> None:
    print(paint("  " + "═" * (WIDTH - 2), C.ACCENT2))


def phase(index: int, total: int, text: str) -> None:
    label = f" {index:02d} / {total:02d} · {text.upper()} "
    pad = max(0, WIDTH - len(label) - 2)
    print()
    print(paint("┃", C.ACCENT) + paint(label, C.BOLD, C.WHITE) + paint("─" * pad, C.DIM))


def section(text: str) -> None:
    head = f"─ {text} "
    print(paint("╭" + head + "─" * max(0, WIDTH - len(head) - 1), C.DIM))


def end_section() -> None:
    print(paint("╰" + "─" * (WIDTH - 1), C.DIM))


def kv(pairs) -> None:
    for key, value in pairs:
        print(f"│  {paint(str(key).ljust(12), C.GREY)} {_fit(value, WIDTH - 17)}")


def finding_card(f) -> None:
    tag = f" {f.prefix} {f.severity} "
    print()
    print(paint("╭" + tag + "─" * max(0, WIDTH - len(tag) - 1), C.DIM))
    for key, value in (("param", f"{f.param}   [{f.method}]"),
                       ("endpoint", f.url),
                       ("payload", f.payload),
                       ("evidence", f.evidence or "(marker matched)")):
        print(f"│  {paint(key.ljust(10), C.GREY)} {_fit(value, WIDTH - 15)}")
    print(paint("╰" + "─" * (WIDTH - 1), C.DIM))


def step(status: str, name: str, detail: str = "", payload: str = "") -> None:
    marks = {
        "CONFIRMED": paint("▸", C.GREEN) + paint(" CONFIRMED ", C.GREEN, C.BOLD),
        "FAILED": paint("▸", C.DIM) + paint(" failed    ", C.DIM),
        "INFO": paint("▸", C.ACCENT2) + paint(" info      ", C.ACCENT2),
    }
    print(f"   {marks.get(status, '▸')} {paint(name, C.WHITE)}")
    if detail:
        print(f"     {paint('│', C.DIM)} {_fit(detail, WIDTH - 9)}")
    if payload and status == "CONFIRMED":
        print(f"     {paint('│', C.DIM)} {paint('payload ', C.DIM)} "
              f"{_fit(payload, WIDTH - 18)}")


def line(text: str, color=None) -> None:
    print(f"   {paint(text, *(color or ()))}")


def bullet(text: str, color=None) -> None:
    print(f"     {paint('·', C.DIM)} {paint(text, *(color or ()))}")
