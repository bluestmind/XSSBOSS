"""Test suite for proxy pool, rotation, fault tolerance, and proxy API."""
from unittest.mock import patch, MagicMock
import inspect
import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend_api.main import app
from backend_api.db.session import get_db
from backend_api.models.base import BaseModel
from backend_api.utils.stealth import (
    _init_proxy_pool,
    get_next_proxy,
    get_proxy_count,
    get_proxy_pool_status,
    mark_proxy_failed,
    mark_proxy_success,
    get_http_proxy_kwargs,
    preflight_check,
)
from backend_api.config import settings


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_proxy_pool_init_and_rotation():
    with patch.object(settings, "PROXY_ENABLED", True),          patch.object(settings, "PROXY_LIST", "http://1.1.1.1:8080,http://2.2.2.2:8080,socks5://3.3.3.3:1080"),          patch.object(settings, "PROXY_ROTATION", "round_robin"):
        _init_proxy_pool()
        assert get_proxy_count() == 3

        p1 = get_next_proxy()
        p2 = get_next_proxy()
        p3 = get_next_proxy()
        p4 = get_next_proxy()

        assert p1 == "http://1.1.1.1:8080"
        assert p2 == "http://2.2.2.2:8080"
        assert p3 == "socks5://3.3.3.3:1080"
        assert p4 == "http://1.1.1.1:8080"


def test_proxy_failure_ejection():
    with patch.object(settings, "PROXY_ENABLED", True),          patch.object(settings, "PROXY_LIST", "http://bad1:80,http://good2:80"),          patch.object(settings, "PROXY_MAX_FAILURES", 2):
        _init_proxy_pool()
        assert get_proxy_count() == 2

        # First failure
        mark_proxy_failed("http://bad1:80")
        assert get_proxy_count() == 2

        # Second failure -> triggers ejection
        mark_proxy_failed("http://bad1:80")
        assert get_proxy_count() == 1
        assert get_next_proxy() == "http://good2:80"

        st = get_proxy_pool_status()
        assert st["active_count"] == 1
        assert st["ejected_count"] == 1


def test_get_http_proxy_kwargs():
    httpx_proxy_key = "proxy" if "proxy" in inspect.signature(httpx.Client).parameters else "proxies"
    with patch.object(settings, "BURP_PROXY_WORKERS", True), \
         patch.object(settings, "BURP_PROXY_URL", "http://127.0.0.1:8080"), \
         patch("backend_api.utils.proxy_health.proxy_reachable", return_value=(True, None)):
        res = get_http_proxy_kwargs(rotated=True)
        assert res == {httpx_proxy_key: "http://127.0.0.1:8080"}

    with patch.object(settings, "PROXY_ENABLED", True), \
         patch.object(settings, "BURP_PROXY_WORKERS", False), \
         patch.object(settings, "PROXY_LIST", "http://10.0.0.1:8080"), \
         patch("backend_api.utils.proxy_health.proxy_reachable", return_value=(True, None)):
        _init_proxy_pool()
        res = get_http_proxy_kwargs(rotated=True)
        assert res == {httpx_proxy_key: "http://10.0.0.1:8080"}
        res_req = get_http_proxy_kwargs(rotated=True, library="requests")
        assert res_req == {"proxies": {"http": "http://10.0.0.1:8080", "https": "http://10.0.0.1:8080"}}


def test_dead_burp_proxy_falls_back_to_direct_network():
    with patch.object(settings, "BURP_PROXY_WORKERS", True), \
         patch.object(settings, "BURP_PROXY_URL", "http://127.0.0.1:8080"), \
         patch.object(settings, "PROXY_URL", None), \
         patch("backend_api.utils.proxy_health.proxy_reachable", return_value=(False, "connection refused")):
        assert get_http_proxy_kwargs(rotated=False) == {}


def test_preflight_bypasses_configured_proxy_for_loopback():
    response = MagicMock(status_code=200, headers={}, url="http://127.0.0.1:8765/")
    with patch.object(settings, "BURP_PROXY_WORKERS", True), \
         patch.object(settings, "BURP_PROXY_URL", "http://127.0.0.1:8080"), \
         patch("requests.head", return_value=response) as request_head:
        result = preflight_check("http://127.0.0.1:8765/")

    assert result["reachable"] is True
    assert "proxies" not in request_head.call_args.kwargs


def test_proxy_api_endpoints(client):
    # 1. GET /api/v1/proxy/status
    res = client.get("/api/v1/proxy/status")
    assert res.status_code == 200
    data = res.json()
    assert "active_count" in data
    assert "rotation_mode" in data

    # 2. POST /api/v1/proxy/refresh
    res = client.post("/api/v1/proxy/refresh")
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    # 3. POST /api/v1/proxy/test with mock
    with patch("backend_api.routers.proxy.httpx.Client") as mock_client_cls:
        mock_instance = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "{\"origin\": \"1.2.3.4\"}"
        mock_instance.get.return_value = mock_resp
        mock_client_cls.return_value.__enter__.return_value = mock_instance

        res = client.post("/api/v1/proxy/test", json={"target_url": "https://httpbin.org/ip", "proxy_url": "http://1.2.3.4:8080"})
        assert res.status_code == 200
        assert res.json()["status"] == "success"
        assert res.json()["status_code"] == 200

    # 4. GET /api/v1/proxy/upstream-server
    res = client.get("/api/v1/proxy/upstream-server")
    assert res.status_code == 200
    assert "port" in res.json()
    assert res.json()["port"] == 8899

    # 5. GET /api/v1/proxy/harvester-status
    res = client.get("/api/v1/proxy/harvester-status")
    assert res.status_code == 200
    assert "active_pool_count" in res.json()

    # 6. POST /api/v1/proxy/harvest (mocked)
    with patch("backend_api.services.proxy_harvester_service.httpx.Client") as mock_http:
        mock_inst = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "10.0.0.1:8080\n10.0.0.2:8080"
        mock_inst.get.return_value = mock_resp
        mock_http.return_value.__enter__.return_value = mock_inst

        res = client.post("/api/v1/proxy/harvest")
        assert res.status_code == 200
        assert res.json()["status"] in ("success", "in_progress")



