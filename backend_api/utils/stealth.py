"""Browser stealth utilities for XSS Boss.

Provides User-Agent rotation, WAF bypass headers, and proxy rotation
to make scanning traffic look more human and avoid fingerprinting.
"""

import itertools
import inspect
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
# Proxy Rotation & Fault Tolerance
# ---------------------------------------------------------------------------

_proxy_lock = threading.Lock()
_proxy_list: list[str] = []
_proxy_cycle = None
_failed_proxy_counts: dict[str, int] = {}
_ejected_proxies: set[str] = set()


def _normalize_proxy_str(proxy: str) -> Optional[str]:
    """Ensure proxy string has a valid protocol prefix."""
    p = proxy.strip()
    if not p or p.startswith("#"):
        return None
    if not (p.startswith("http://") or p.startswith("https://") or p.startswith("socks5://") or p.startswith("socks4://")):
        p = f"http://{p}"
    return p


def _init_proxy_pool():
    """Initialize proxy pool from config string or file (e.g. proxies.txt)."""
    global _proxy_list, _proxy_cycle, _failed_proxy_counts, _ejected_proxies

    if not getattr(settings, "PROXY_ENABLED", True):
        _proxy_list = []
        _proxy_cycle = None
        return

    raw = getattr(settings, "PROXY_LIST", "").strip()
    proxies: list[str] = []

    # 1. Load from comma-separated string if provided
    if raw:
        for p in raw.split(","):
            norm = _normalize_proxy_str(p)
            if norm:
                proxies.append(norm)

    # 2. If no string list, load from proxy list file (e.g. proxies.txt)
    if not proxies:
        proxy_file = getattr(settings, "PROXY_LIST_FILE", "proxies.txt")
        if proxy_file:
            from pathlib import Path
            candidates = [
                Path(proxy_file),
                Path.cwd() / proxy_file,
                Path(__file__).resolve().parent.parent.parent / proxy_file,
            ]
            for candidate in candidates:
                if candidate.exists() and candidate.is_file():
                    try:
                        with open(candidate, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                norm = _normalize_proxy_str(line)
                                if norm:
                                    proxies.append(norm)
                        if proxies:
                            logger.info(f"[Stealth] Loaded {len(proxies)} proxies from {candidate}")
                            break
                    except Exception as e:
                        logger.warning(f"[Stealth] Failed to read proxy file {candidate}: {e}")

    # Remove duplicates while preserving order
    deduped = list(dict.fromkeys(proxies))
    _proxy_list = deduped
    _failed_proxy_counts = {}
    _ejected_proxies = set()

    if _proxy_list:
        _proxy_cycle = itertools.cycle(_proxy_list)
        logger.info(f"[Stealth] Proxy pool initialized with {len(_proxy_list)} active proxies")
    else:
        _proxy_cycle = None


def get_next_proxy() -> Optional[str]:
    """Return the next proxy URL in rotation, or None if no proxies configured."""
    global _proxy_cycle
    if _proxy_cycle is None:
        _init_proxy_pool()
    if not _proxy_list:
        return getattr(settings, "PROXY_URL", None)
    with _proxy_lock:
        if not _proxy_list:
            return getattr(settings, "PROXY_URL", None)
        if getattr(settings, "PROXY_ROTATION", "round_robin") == "random":
            return random.choice(_proxy_list)
        return next(_proxy_cycle) if _proxy_cycle else None


def mark_proxy_failed(proxy_url: Optional[str]) -> None:
    """Record a connection failure for a proxy and eject if threshold exceeded."""
    if not proxy_url:
        return
    max_fails = getattr(settings, "PROXY_MAX_FAILURES", 3)
    with _proxy_lock:
        count = _failed_proxy_counts.get(proxy_url, 0) + 1
        _failed_proxy_counts[proxy_url] = count
        if count >= max_fails and proxy_url in _proxy_list:
            _proxy_list.remove(proxy_url)
            _ejected_proxies.add(proxy_url)
            global _proxy_cycle
            _proxy_cycle = itertools.cycle(_proxy_list) if _proxy_list else None
            logger.warning(f"[Stealth] Ejected failing proxy {proxy_url} (failed {count} times). Remaining active: {len(_proxy_list)}")


def mark_proxy_success(proxy_url: Optional[str]) -> None:
    """Reset failure counter for a proxy that successfully connected."""
    if not proxy_url:
        return
    with _proxy_lock:
        if proxy_url in _failed_proxy_counts:
            _failed_proxy_counts[proxy_url] = 0


def get_proxy_count() -> int:
    """Return how many proxies are currently available."""
    if not _proxy_list and _proxy_cycle is None:
        _init_proxy_pool()
    return len(_proxy_list)


def get_proxy_pool_status() -> dict:
    """Return live status of the proxy pool and failure metrics."""
    if not _proxy_list and _proxy_cycle is None:
        _init_proxy_pool()
    return {
        "enabled": getattr(settings, "PROXY_ENABLED", True),
        "active_count": len(_proxy_list),
        "ejected_count": len(_ejected_proxies),
        "rotation_mode": getattr(settings, "PROXY_ROTATION", "round_robin"),
        "static_proxy": getattr(settings, "PROXY_URL", None),
        "burp_proxy": getattr(settings, "BURP_PROXY_URL", None) if getattr(settings, "BURP_PROXY_WORKERS", False) else None,
    }


def get_http_proxy_kwargs(rotated: bool = True, library: str = "httpx") -> dict:
    """Return proxy kwargs compatible with the installed HTTP client version."""
    from backend_api.utils.proxy_health import effective_worker_proxy

    rotated_proxy = get_next_proxy() if rotated else None
    proxy = effective_worker_proxy(rotated_proxy)

    if proxy:
        if library == "requests":
            return {"proxies": {"http": proxy, "https": proxy}}
        # httpx 0.28 renamed ``proxies`` to ``proxy``. Runtime detection keeps
        # workers usable when the host environment is newer than requirements.
        import httpx
        parameter = "proxy" if "proxy" in inspect.signature(httpx.Client).parameters else "proxies"
        return {parameter: proxy}
    return {}


# ---------------------------------------------------------------------------
# Pre-Scan Reachability Probe
# ---------------------------------------------------------------------------

def _is_loopback_url(url: str) -> bool:
    """Return true when a target must be reached directly from this host."""
    from ipaddress import ip_address
    from urllib.parse import urlsplit

    hostname = (urlsplit(url).hostname or "").strip().lower().rstrip(".")
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".localhost"):
        return True
    try:
        return ip_address(hostname).is_loopback
    except ValueError:
        return False

def preflight_check(url: str, timeout: float = 10.0) -> dict:
    """Send lightweight probe requests to verify target is reachable.

    Features:
    - Passes configured proxy kwargs (Burp / static / rotated) to avoid local DNS failures
    - Tries HEAD first; falls back to GET with stream=True if HEAD is 405/rejected
    - If http:// fails connection or DNS, automatically attempts https:// fallback
    - Treats active web server status codes (including 403, 401, 404, 429, 446, 503) as reachable
    - Returns effective_url if scheme or redirection fallback succeeded
    """
    import requests as _requests

    candidate_urls = [url]
    if url.startswith("http://"):
        candidate_urls.append("https://" + url[7:])
    elif url.startswith("https://"):
        candidate_urls.append("http://" + url[8:])

    last_error = None
    # A host-local target cannot be reached through a Burp/static proxy bound to
    # another process. Respect the operator's proxy for remote targets, while
    # guaranteeing that localhost acceptance targets remain directly testable.
    proxy_kwargs = (
        {}
        if _is_loopback_url(url)
        else get_http_proxy_kwargs(rotated=False, library="requests")
    )

    for candidate in candidate_urls:
        headers = {
            "User-Agent": get_random_user_agent(),
            **get_random_waf_bypass_headers(),
        }
        # Try HEAD first
        try:
            resp = _requests.head(
                candidate,
                timeout=timeout,
                allow_redirects=True,
                verify=not settings.ALLOW_INSECURE_TLS,
                headers=headers,
                **proxy_kwargs,
            )
            # If 405 Method Not Allowed or 400, try GET
            if resp.status_code in {405, 400}:
                resp = _requests.get(
                    candidate,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=not settings.ALLOW_INSECURE_TLS,
                    headers=headers,
                    stream=True,
                    **proxy_kwargs,
                )

            retry_after = None
            if resp.headers.get("Retry-After"):
                try:
                    retry_after = float(resp.headers["Retry-After"])
                except (ValueError, TypeError):
                    pass

            return {
                "reachable": True,
                "status_code": resp.status_code,
                "effective_url": str(resp.url) if resp.url else candidate,
                "error": None,
                "retry_after": retry_after,
            }
        except (_requests.exceptions.ConnectionError, _requests.exceptions.Timeout) as e:
            # Try GET before giving up on candidate
            try:
                resp = _requests.get(
                    candidate,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=not settings.ALLOW_INSECURE_TLS,
                    headers=headers,
                    stream=True,
                    **proxy_kwargs,
                )
                return {
                    "reachable": True,
                    "status_code": resp.status_code,
                    "effective_url": str(resp.url) if resp.url else candidate,
                    "error": None,
                    "retry_after": None,
                }
            except Exception as get_err:
                last_error = str(get_err)
        except Exception as e:
            last_error = str(e)

    return {
        "reachable": False,
        "status_code": None,
        "effective_url": url,
        "error": last_error or f"Target {url} is unreachable on HTTP/HTTPS",
        "retry_after": None,
    }
