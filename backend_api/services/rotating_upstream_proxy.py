"""Dynamic Rotating Upstream Proxy Server for Burp Suite and External Tools.

Provides a local forwarding proxy on 127.0.0.1:8899 that dynamically rotates
every outbound request across all active proxies in the proxy pool (proxies.txt).
Burp Suite points to this single upstream proxy rule (* -> 127.0.0.1:8899),
giving Burp dynamic, per-request proxy rotation and automatic failover.
"""

import json
import os
import re
import select
import socket
import threading
import time
from urllib.parse import urlparse
from typing import Optional, Tuple

from backend_api.config import settings
from backend_api.utils.logger import logger
from backend_api.utils.stealth import (
    get_next_proxy,
    mark_proxy_failed,
    mark_proxy_success,
    get_proxy_count,
)


class RotatingUpstreamProxyServer:
    """Threaded HTTP/HTTPS CONNECT proxy server that dynamically rotates upstream proxies."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8899):
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        """Start the rotating upstream proxy server in a background daemon thread."""
        if self._running:
            return True
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(128)
            self._running = True

            self._thread = threading.Thread(
                target=self._accept_loop,
                name="RotatingUpstreamProxyDaemon",
                daemon=True,
            )
            self._thread.start()
            logger.info(
                f"[UpstreamProxy] Dynamic Rotating Proxy Server running on {self.host}:{self.port} "
                f"({get_proxy_count()} upstream pool proxies)"
            )
            self._write_burp_config()
            return True
        except Exception as e:
            logger.error(f"[UpstreamProxy] Failed to start on {self.host}:{self.port}: {e}")
            self._running = False
            return False

    def stop(self) -> None:
        """Stop the proxy server and close listening socket."""
        self._running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None
        logger.info("[UpstreamProxy] Dynamic Rotating Proxy Server stopped")

    def _write_burp_config(self) -> None:
        """Write project options JSON file ready to import into Burp Suite."""
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "burp_upstream_proxy.json")
        burp_config = {
            "project_options": {
                "connections": {
                    "upstream_proxy_rules": [
                        {
                            "destination_host": "*",
                            "proxy_host": self.host,
                            "proxy_port": self.port,
                            "auth_type": "none",
                            "enabled": True
                        }
                    ]
                }
            }
        }
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(burp_config, f, indent=2)
            logger.info(f"[UpstreamProxy] Burp configuration file written to {config_path}")
        except Exception as e:
            logger.debug(f"[UpstreamProxy] Could not write Burp config file: {e}")

    def _accept_loop(self) -> None:
        """Accept incoming connections from Burp Suite or other tools."""
        while self._running and self.server_socket:
            try:
                client_sock, client_addr = self.server_socket.accept()
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, client_addr),
                    daemon=True,
                )
                t.start()
            except Exception:
                if not self._running:
                    break

    def _handle_client(self, client_sock: socket.socket, client_addr: Tuple[str, int]) -> None:
        """Handle individual client connection with dynamic upstream rotation."""
        client_sock.settimeout(15.0)
        try:
            raw_request = b""
            while b"\r\n\r\n" not in raw_request:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                raw_request += chunk
                if len(raw_request) > 65536:
                    break

            if not raw_request:
                client_sock.close()
                return

            first_line = raw_request.split(b"\r\n")[0].decode("latin-1", errors="ignore")
            parts = first_line.split()
            if len(parts) < 2:
                client_sock.close()
                return

            method, target_uri = parts[0].upper(), parts[1]

            if method == "CONNECT":
                self._handle_connect(client_sock, target_uri)
            else:
                self._handle_http_forward(client_sock, raw_request, target_uri)

        except Exception as e:
            logger.debug(f"[UpstreamProxy] Client handler error: {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _handle_connect(self, client_sock: socket.socket, target_uri: str) -> None:
        """Tunnel HTTPS CONNECT requests through dynamically selected upstream proxy."""
        if ":" in target_uri:
            target_host, target_port_str = target_uri.split(":", 1)
            try:
                target_port = int(target_port_str)
            except ValueError:
                target_port = 443
        else:
            target_host, target_port = target_uri, 443

        max_attempts = 3
        upstream_sock = None
        used_proxy = None

        for _ in range(max_attempts):
            used_proxy = get_next_proxy()
            if not used_proxy:
                # Direct connection fallback
                try:
                    upstream_sock = socket.create_connection((target_host, target_port), timeout=8.0)
                    client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    break
                except Exception as direct_err:
                    logger.debug(f"[UpstreamProxy] Direct connect to {target_host}:{target_port} failed: {direct_err}")
                    break

            # Connect via Upstream Proxy
            try:
                parsed = urlparse(used_proxy)
                proxy_host = parsed.hostname or "127.0.0.1"
                proxy_port = parsed.port or (80 if parsed.scheme == "http" else 8080)

                upstream_sock = socket.create_connection((proxy_host, proxy_port), timeout=6.0)
                connect_payload = (
                    f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                    f"Host: {target_host}:{target_port}\r\n"
                    f"Proxy-Connection: Keep-Alive\r\n\r\n"
                ).encode("latin-1")
                upstream_sock.sendall(connect_payload)

                # Read upstream proxy CONNECT response
                response = b""
                upstream_sock.settimeout(6.0)
                while b"\r\n\r\n" not in response:
                    chunk = upstream_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 8192:
                        break

                if b" 200 " in response or b" 200\r\n" in response:
                    client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    mark_proxy_success(used_proxy)
                    break
                else:
                    mark_proxy_failed(used_proxy)
                    upstream_sock.close()
                    upstream_sock = None
            except Exception as proxy_err:
                mark_proxy_failed(used_proxy)
                if upstream_sock:
                    try:
                        upstream_sock.close()
                    except Exception:
                        pass
                    upstream_sock = None

        if not upstream_sock:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway (Upstream Proxy Failure)\r\n\r\n")
            return

        # Bi-directional socket forwarding
        self._pipe_sockets(client_sock, upstream_sock)

    def _handle_http_forward(self, client_sock: socket.socket, raw_request: bytes, target_uri: str) -> None:
        """Forward plain HTTP requests through dynamically selected upstream proxy."""
        used_proxy = get_next_proxy()
        parsed_target = urlparse(target_uri if target_uri.startswith("http") else f"http://{target_uri}")
        target_host = parsed_target.hostname or "127.0.0.1"
        target_port = parsed_target.port or 80

        upstream_sock = None
        if used_proxy:
            try:
                parsed = urlparse(used_proxy)
                proxy_host = parsed.hostname or "127.0.0.1"
                proxy_port = parsed.port or (80 if parsed.scheme == "http" else 8080)
                upstream_sock = socket.create_connection((proxy_host, proxy_port), timeout=8.0)
                upstream_sock.sendall(raw_request)
                mark_proxy_success(used_proxy)
            except Exception:
                mark_proxy_failed(used_proxy)
                upstream_sock = None

        if not upstream_sock:
            try:
                upstream_sock = socket.create_connection((target_host, target_port), timeout=8.0)
                upstream_sock.sendall(raw_request)
            except Exception:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return

        self._pipe_sockets(client_sock, upstream_sock)

    def _pipe_sockets(self, sock1: socket.socket, sock2: socket.socket) -> None:
        """Bi-directional byte pump between two sockets."""
        sock1.setblocking(False)
        sock2.setblocking(False)
        sockets = [sock1, sock2]

        try:
            while True:
                rlist, _, xlist = select.select(sockets, [], sockets, 30.0)
                if xlist or not rlist:
                    break
                for s in rlist:
                    other = sock2 if s is sock1 else sock1
                    try:
                        data = s.recv(16384)
                        if not data:
                            return
                        other.sendall(data)
                    except Exception:
                        return
        finally:
            for s in sockets:
                try:
                    s.close()
                except Exception:
                    pass


# Singleton instance
_upstream_proxy_server: Optional[RotatingUpstreamProxyServer] = None
_upstream_proxy_lock = threading.Lock()


def get_rotating_upstream_proxy_server() -> RotatingUpstreamProxyServer:
    """Return or create singleton RotatingUpstreamProxyServer."""
    global _upstream_proxy_server
    if _upstream_proxy_server is None:
        with _upstream_proxy_lock:
            if _upstream_proxy_server is None:
                _upstream_proxy_server = RotatingUpstreamProxyServer(
                    host=settings.UPSTREAM_ROTATING_PROXY_HOST,
                    port=settings.UPSTREAM_ROTATING_PROXY_PORT,
                )
    return _upstream_proxy_server
