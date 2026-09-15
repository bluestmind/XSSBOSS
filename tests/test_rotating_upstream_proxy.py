"""Tests for the dynamic rotating upstream proxy server for Burp Suite."""

import socket
import threading
import time
from unittest.mock import patch
from backend_api.services.rotating_upstream_proxy import RotatingUpstreamProxyServer


def test_rotating_upstream_proxy_server_lifecycle():
    """Verify server binds, accepts connections, and gracefully shuts down."""
    # Find free port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    server = RotatingUpstreamProxyServer(host="127.0.0.1", port=port)
    assert server.start() is True

    # Test connecting
    client = socket.create_connection(("127.0.0.1", port), timeout=3.0)
    assert client is not None
    client.close()

    server.stop()
    assert server._running is False
