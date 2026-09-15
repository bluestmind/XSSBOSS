"""Proxy Pool and Health API endpoints."""
import time
import httpx
from fastapi import APIRouter, HTTPException, Query
from typing import Optional, Dict, Any
from pydantic import BaseModel

from backend_api.config import settings
from backend_api.utils.stealth import (
    get_proxy_pool_status,
    get_next_proxy,
    get_proxy_count,
    _init_proxy_pool,
    mark_proxy_failed,
    mark_proxy_success,
    preflight_check,
)
from backend_api.utils.logger import logger

router = APIRouter(prefix="/proxy", tags=["proxy"])


class ProxyTestRequest(BaseModel):
    target_url: str = "https://httpbin.org/ip"
    proxy_url: Optional[str] = None
    timeout: float = 5.0


@router.get("/status")
def proxy_status() -> Dict[str, Any]:
    """Get active proxy pool metrics and rotation state."""
    return get_proxy_pool_status()


@router.post("/refresh")
def refresh_proxy_pool() -> Dict[str, Any]:
    """Reload proxies from configured string or proxies.txt file."""
    _init_proxy_pool()
    status = get_proxy_pool_status()
    logger.info(f"Proxy pool refreshed: {status['active_count']} active proxies")
    return {"status": "success", "pool": status}


@router.post("/test")
def test_proxy(req: ProxyTestRequest) -> Dict[str, Any]:
    """Test connectivity through the proxy pool or a specific proxy server."""
    import time
    import httpx

    target = req.target_url
    proxy = req.proxy_url or get_next_proxy()

    if not proxy:
        return {
            "status": "direct",
            "proxy": None,
            "message": "No proxy configured; request would run direct.",
            "check": preflight_check(target, timeout=req.timeout),
        }

    start = time.time()
    try:
        with httpx.Client(
            proxy=proxy,
            timeout=req.timeout,
            verify=not settings.ALLOW_INSECURE_TLS,
            follow_redirects=True,
        ) as client:
            from backend_api.utils.rate_limiter import rate_limited_call

            resp = rate_limited_call(target, lambda: client.get(target))
            latency_ms = (time.time() - start) * 1000
            mark_proxy_success(proxy)
            return {
                "status": "success",
                "proxy": proxy,
                "status_code": resp.status_code,
                "latency_ms": round(latency_ms, 2),
                "response_body_preview": resp.text[:200],
            }
    except Exception as exc:
        mark_proxy_failed(proxy)
        return {
            "status": "failed",
            "proxy": proxy,
            "error": str(exc),
            "latency_ms": round((time.time() - start) * 1000, 2),
        }


@router.get("/upstream-server")
def get_upstream_server_info() -> Dict[str, Any]:
    """Get dynamic upstream proxy adapter information for Burp Suite."""
    from backend_api.config import settings
    from backend_api.services.rotating_upstream_proxy import get_rotating_upstream_proxy_server

    server = get_rotating_upstream_proxy_server()
    return {
        "enabled": getattr(settings, "UPSTREAM_ROTATING_PROXY_ENABLED", True),
        "host": server.host,
        "port": server.port,
        "proxy_url": f"http://{server.host}:{server.port}",
        "active_proxies_in_pool": get_proxy_count(),
        "burp_rule": {
            "destination_host": "*",
            "proxy_host": server.host,
            "proxy_port": server.port,
        },
        "description": "Burp Suite sends traffic to this single endpoint; it automatically rotates through the entire proxy pool on every request.",
    }


@router.post("/harvest")
def harvest_fresh_proxies() -> Dict[str, Any]:
    """Trigger background harvest of fresh proxies from top public repositories."""
    from backend_api.services.proxy_harvester_service import get_proxy_harvester_service

    harvester = get_proxy_harvester_service()
    res = harvester.harvest_and_refresh()
    return res


@router.get("/harvester-status")
def get_harvester_status() -> Dict[str, Any]:
    """Get auto-harvester metrics and last refresh timestamp."""
    from backend_api.services.proxy_harvester_service import get_proxy_harvester_service

    harvester = get_proxy_harvester_service()
    return harvester.get_status()


