"""Fast health-aware proxy selection for optional browser/HTTP integrations."""
from __future__ import annotations

import socket
import threading
import time
from typing import Any, Optional
from urllib.parse import urlparse

from backend_api.config import settings
from backend_api.utils.logger import logger


_CACHE_TTL_SECONDS = 5.0
_cache: dict[str, tuple[float, bool, Optional[str]]] = {}
_cache_lock = threading.Lock()


def proxy_reachable(proxy_url: str, timeout_seconds: float = 0.35) -> tuple[bool, Optional[str]]:
    """Return whether a configured proxy has a reachable TCP listener."""
    parsed = urlparse(proxy_url)
    host = parsed.hostname
    port = parsed.port
    if not host or not port:
        return False, "proxy URL must include host and port"
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(proxy_url)
        if cached and now - cached[0] <= _CACHE_TTL_SECONDS:
            return cached[1], cached[2]
    try:
        with socket.create_connection((host, port), timeout=max(0.05, timeout_seconds)):
            result = (True, None)
    except OSError as error:
        result = (False, str(error))
    with _cache_lock:
        _cache[proxy_url] = (now, result[0], result[1])
    return result


def resolve_worker_proxy(rotated_proxy: Optional[str] = None) -> dict[str, Any]:
    """Pick the first live configured proxy or explicitly fall back to direct."""
    candidates: list[tuple[str, Optional[str]]] = []
    if getattr(settings, "BURP_PROXY_WORKERS", False):
        candidates.append(("burp", getattr(settings, "BURP_PROXY_URL", None)))
    if rotated_proxy:
        candidates.append(("rotated", rotated_proxy))
    configured_default = getattr(settings, "PROXY_URL", None)
    if configured_default and configured_default != rotated_proxy:
        candidates.append(("default", configured_default))

    checked: list[dict[str, Any]] = []
    for source, candidate in candidates:
        if not candidate:
            continue
        reachable, error = proxy_reachable(candidate)
        checked.append({"source": source, "url": candidate, "reachable": reachable, "error": error})
        if reachable:
            return {
                "source": source,
                "url": candidate,
                "reachable": True,
                "fallback_direct": False,
                "checked": checked,
            }

    if checked:
        logger.warning("All configured worker proxies are unreachable; using direct network access")
    return {
        "source": "direct",
        "url": None,
        "reachable": True,
        "fallback_direct": bool(checked),
        "checked": checked,
    }


def effective_worker_proxy(rotated_proxy: Optional[str] = None) -> Optional[str]:
    return resolve_worker_proxy(rotated_proxy).get("url")
