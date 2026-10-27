"""
SpectreHunt :: utils/callback.py
Local HTTP server used to PROVE Remote File Inclusion, plus LAN IP discovery.

Author : Inayat Hussain
"""

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from config import RFI_PAYLOAD_BODY, RFI_PAYLOAD_FILENAME, log


def local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


class _Handler(BaseHTTPRequestHandler):
    server_version = "SpectreHunt/5.1"

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        self.server.hits.append(self.path)
        if path in ("/", "/" + RFI_PAYLOAD_FILENAME):
            body = RFI_PAYLOAD_BODY.encode()
        else:
            body = f"<?php echo 'RFI_{path.strip('/')}'; ?>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class CallbackServer:
    def __init__(self, port: int = 0, host: str | None = None, tries: int = 12):
        self.host = host or local_ip()
        self.httpd = None
        self.port = port
        last_error = None

        if port == 0:
            server = ThreadingHTTPServer(("0.0.0.0", 0), _Handler)
            server.daemon_threads = True
            self.httpd = server
            self.port = server.server_address[1]
        else:
            for offset in range(tries):
                try:
                    server = ThreadingHTTPServer(("0.0.0.0", port + offset), _Handler)
                    server.daemon_threads = True
                    self.httpd = server
                    self.port = port + offset
                    break
                except OSError as exc:
                    last_error = exc

        if self.httpd is None:
            raise last_error or OSError("could not bind callback port")

        self.httpd.hits = []
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def hits(self) -> list:
        return self.httpd.hits

    @property
    def url(self) -> str:
        return f"{self.host}:{self.port}"

    def start(self) -> str:
        self.thread.start()
        return self.url

    def stop(self) -> None:
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except Exception:
            pass
