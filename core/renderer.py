"""
SpectreHunt :: core/renderer.py
Optional Playwright renderer so JavaScript SPAs yield real links.

Author : Inayat Hussain
"""

from __future__ import annotations

import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    import playwright as _playwright_pkg
    from playwright.sync_api import sync_playwright

    PLAYWRIGHT_AVAILABLE = True
except Exception:
    _playwright_pkg = None
    sync_playwright = None
    PLAYWRIGHT_AVAILABLE = False

PIP_FIX = ("sudo apt remove -y python3-playwright && "
           "pip install --break-system-packages playwright && "
           "python3 -m playwright install chromium")


def _bundled_driver() -> bool:
    try:
        return (Path(_playwright_pkg.__file__).parent / "driver").is_dir()
    except Exception:
        return False


def preflight() -> str | None:
    if not PLAYWRIGHT_AVAILABLE:
        return ("python playwright missing -- pip install --break-system-packages "
                "playwright && python3 -m playwright install chromium")
    if _bundled_driver():
        return None
    if not shutil.which("node"):
        return "distro playwright with no bundled driver and no node -- " + PIP_FIX
    if not Path("/usr/share/nodejs/playwright/cli.js").exists():
        return "distro playwright driver missing -- " + PIP_FIX
    return None


class Renderer:
    def __init__(self, timeout_ms: int = 25000, settle_ms: int = 1500):
        reason = preflight()
        if reason:
            raise RuntimeError(reason)

        self.timeout_ms = timeout_ms
        self.settle_ms = settle_ms
        self.rendered = 0
        self._pool = ThreadPoolExecutor(max_workers=1)
        self._browser = None
        self._ctx = None
        self._playwright = None

        try:
            self._pool.submit(self._start).result()
        except Exception as exc:
            self._pool.shutdown(wait=False)
            raise RuntimeError(self._explain(exc)) from exc

    @staticmethod
    def _explain(exc: Exception) -> str:
        msg = str(exc)
        low = msg.lower()
        if "cli.js" in msg or "module_not_found" in low:
            return "playwright node driver missing -- " + PIP_FIX
        if "executable doesn't exist" in low:
            return "chromium not installed -- python3 -m playwright install chromium"
        if "connection closed" in low or "_playwright" in msg:
            return "playwright driver died at startup -- " + PIP_FIX
        return msg

    def _start(self) -> None:
        self._ctx = sync_playwright()
        try:
            self._playwright = self._ctx.start()
        except AttributeError:
            self._playwright = self._ctx.__enter__()
        self._browser = self._playwright.chromium.launch(headless=True)

    def _render_sync(self, url: str):
        page = self._browser.new_page()
        try:
            page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
            page.wait_for_timeout(self.settle_ms)
            html = page.content()
            final_url = page.url
            self.rendered += 1
            return html, final_url
        except Exception:
            return None, url
        finally:
            try:
                page.close()
            except Exception:
                pass

    def render(self, url: str):
        try:
            return self._pool.submit(self._render_sync, url).result()
        except Exception:
            return None, url

    def close(self) -> None:
        def _shutdown():
            for target, method in ((self._browser, "close"), (self._playwright, "stop")):
                try:
                    if target is not None:
                        getattr(target, method)()
                except Exception:
                    pass

        try:
            self._pool.submit(_shutdown).result()
        except Exception:
            pass
        finally:
            self._pool.shutdown(wait=False)
