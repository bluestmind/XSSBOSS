"""Ephemeral local HTTP server for browser PoC pages."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Optional
from urllib.parse import urlparse


class LocalPoCServer:
    """Serve a single PoC HTML document from 127.0.0.1 on an ephemeral port."""

    def __init__(self, html: str, host: str = "127.0.0.1", port: int = 0):
        self.html = html
        self.host = host
        self.port = port
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[Thread] = None

    def start(self) -> str:
        """Start the server and return the PoC URL."""
        html_bytes = self.html.encode("utf-8")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path not in ("/", "/poc"):
                    self.send_response(404)
                    self.end_headers()
                    return

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html_bytes)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(html_bytes)

            def log_message(self, format, *args):
                return

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self._server.server_address[1]
        self._thread = Thread(target=self._server.serve_forever, name="local-poc-server", daemon=True)
        self._thread.start()
        return f"http://{self.host}:{self.port}/poc"

    def stop(self):
        """Stop the server."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
