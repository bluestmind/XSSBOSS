"""Browser stealth utilities for XSS Boss.

Provides User-Agent rotation, WAF bypass headers, and proxy rotation
to make scanning traffic look more human and avoid fingerprinting.
"""

import itertools
import random
import threading
from typing import Optional

from backend_api.config import settings
from backend_api.utils.logger import logger


# ---------------------------------------------------------------------------
# Realistic User-Agent pool — real Chrome/Firefox strings from 2024-2025
# ---------------------------------------------------------------------------

_USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]


# ---------------------------------------------------------------------------
# WAF bypass headers — tricks that work against misconfigured WAFs
# ---------------------------------------------------------------------------

_WAF_BYPASS_HEADERS = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "X-Remote-IP": "127.0.0.1",
    "X-Remote-Addr": "127.0.0.1",
    "X-Client-IP": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
    "X-Forwarded-Host": "localhost",
}


# ---------------------------------------------------------------------------
# UA Rotation
# ---------------------------------------------------------------------------

_ua_lock = threading.Lock()
_ua_cycle = itertools.cycle(_USER_AGENTS)


def get_random_user_agent() -> str:
    """Return a random realistic User-Agent string."""
    if not settings.ROTATE_USER_AGENT:
        return _USER_AGENTS[0]  # default static UA
    return random.choice(_USER_AGENTS)


def get_next_user_agent() -> str:
    """Return the next User-Agent in round-robin order."""
    if not settings.ROTATE_USER_AGENT:
        return _USER_AGENTS[0]
    with _ua_lock:
        return next(_ua_cycle)


# ---------------------------------------------------------------------------
# WAF Bypass Headers
# ---------------------------------------------------------------------------

def get_waf_bypass_headers() -> dict:
    """Return WAF bypass headers to inject into requests."""
    if not settings.WAF_BYPASS_HEADERS:
        return {}
    return dict(_WAF_BYPASS_HEADERS)


def get_random_waf_bypass_headers() -> dict:
    """Return WAF bypass headers with randomized internal IPs."""
    if not settings.WAF_BYPASS_HEADERS:
        return {}
    # Randomize between common internal IPs to avoid detection of fixed values
    internal_ips = [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "192.168.0.1",
        "10.10.10.1",
    ]
    ip = random.choice(internal_ips)
    return {
        "X-Forwarded-For": ip,
        "X-Originating-IP": ip,
        "X-Remote-IP": ip,
        "X-Remote-Addr": ip,
        "X-Client-IP": ip,
        "X-Real-IP": ip,
    }


# ---------------------------------------------------------------------------
# Proxy Rotation
# ---------------------------------------------------------------------------

_proxy_lock = threading.Lock()
_proxy_list: list[str] = []
_proxy_cycle = None


def _init_proxy_pool():
    """Initialize proxy pool from config."""
    global _proxy_list, _proxy_cycle
    raw = settings.PROXY_LIST.strip()
    if not raw:
        _proxy_list = []
        _proxy_cycle = None
        return
    _proxy_list = [p.strip() for p in raw.split(",") if p.strip()]
    if _proxy_list:
        _proxy_cycle = itertools.cycle(_proxy_list)
        logger.info(f"[Stealth] Proxy pool initialized with {len(_proxy_list)} proxies")


def get_next_proxy() -> Optional[str]:
    """Return the next proxy URL in rotation, or None if no proxies configured."""
    global _proxy_cycle
    if _proxy_cycle is None:
        _init_proxy_pool()
    if not _proxy_list:
        return None
    with _proxy_lock:
        if settings.PROXY_ROTATION == "random":
            return random.choice(_proxy_list)
        return next(_proxy_cycle) if _proxy_cycle else None


def get_proxy_count() -> int:
    """Return how many proxies are available."""
    if not _proxy_list:
        _init_proxy_pool()
    return len(_proxy_list)


# ---------------------------------------------------------------------------
# Pre-Scan Reachability Probe
# ---------------------------------------------------------------------------

def preflight_check(url: str, timeout: float = 10.0) -> dict:
    """Send a lightweight HEAD request to verify target is reachable.

    Returns dict with:
        reachable (bool): True if target responded with status < 500
        status_code (int|None): HTTP status code
        error (str|None): Error message if not reachable
        retry_after (float|None): Retry-After header value if present
    """
    import requests as _requests

    try:
        resp = _requests.head(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={
                "User-Agent": get_random_user_agent(),
                **get_random_waf_bypass_headers(),
            },
        )
        retry_after = None
        if resp.headers.get("Retry-After"):
            try:
                retry_after = float(resp.headers["Retry-After"])
            except (ValueError, TypeError):
                pass

        return {
            "reachable": resp.status_code < 500,
            "status_code": resp.status_code,
            "error": None if resp.status_code < 500 else f"HTTP {resp.status_code}",
            "retry_after": retry_after,
        }
    except _requests.exceptions.Timeout:
        return {"reachable": False, "status_code": None, "error": "Connection timed out", "retry_after": None}
    except _requests.exceptions.ConnectionError as e:
        return {"reachable": False, "status_code": None, "error": f"Connection error: {e}", "retry_after": None}
    except Exception as e:
        return {"reachable": False, "status_code": None, "error": str(e), "retry_after": None}
