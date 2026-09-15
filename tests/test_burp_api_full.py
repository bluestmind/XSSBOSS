"""Comprehensive test suite verifying all Burp Suite API endpoints."""
import base64
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend_api.main import app
from backend_api.db.session import get_db
from backend_api.models.base import BaseModel
from backend_api.models.target import Target
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.finding import Finding, Severity, FindingStatus
from backend_api.models.test_case import TestCase
from backend_api.routers.burp import repeater_queue, findings_queue, active_collaborator_payloads


# Setup in-memory SQLite database
@pytest.fixture
def test_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    BaseModel.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(test_db):
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_get_burp_runtime_status(client):
    with patch("backend_api.routers.burp.BurpRuntimeService.process_state", return_value={"running": True, "pid": 1234, "process_name": "java.exe"}), \
         patch("backend_api.routers.burp.BurpRuntimeService.api_ready", return_value=True):
        res = client.get("/api/v1/burp/runtime")
        assert res.status_code == 200
        data = res.json()
        assert data["running"] is True
        assert data["api_ready"] is True
        assert data["configured"] is True


def test_post_burp_runtime_start(client):
    with patch("backend_api.routers.burp.BurpRuntimeService.ensure_available", return_value={"status": "ready", "started": True, "pid": 1234}):
        res = client.post("/api/v1/burp/runtime/start")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ready"
        assert data["started"] is True


def test_import_burp_xml(client, test_db):
    target = Target(name="Test Target", base_url="http://example.com")
    test_db.add(target)
    test_db.commit()

    sample_xml = """<?xml version="1.0"?>
    <items>
      <item>
        <url>http://example.com/search?q=test</url>
        <host ip="93.184.216.34">example.com</host>
        <port>80</port>
        <protocol>http</protocol>
        <method>GET</method>
        <path>/search</path>
        <request base64="true">R0VUIC9zZWFyY2g/cT10ZXN0IEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KDQo=</request>
        <status>200</status>
      </item>
    </items>"""

    files = {"file": ("burp_export.xml", sample_xml.encode("utf-8"), "application/xml")}
    data = {"target_id": target.id}
    res = client.post("/api/v1/burp/xml", data=data, files=files)
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["status"] == "success"
    assert res_data["imported_count"] >= 1


def test_post_burp_rest_import(client, test_db):
    target = Target(name="Test Target", base_url="http://example.com")
    test_db.add(target)
    test_db.commit()

    with patch("backend_api.routers.burp.BurpService.import_from_rest", return_value={"status": "success", "imported": 5}):
        res = client.post(
            "/api/v1/burp/rest-import",
            json={"target_id": target.id, "api_url": "http://127.0.0.1:13337", "task_id": "1"},
        )
        assert res.status_code == 200
        assert res.json()["status"] == "success"


def test_post_auto_sync(client, test_db):
    target = Target(name="Test Target", base_url="http://example.com")
    test_db.add(target)
    test_db.commit()

    with patch("backend_api.routers.burp.BurpService.auto_scan_and_sync", return_value={"status": "started", "task_id": "99"}):
        res = client.post(f"/api/v1/burp/auto-sync/{target.id}")
        assert res.status_code == 200
        assert res.json()["status"] == "started"


def test_post_trigger_scan(client):
    with patch("backend_api.routers.burp.BurpService.trigger_scan", return_value={"status": "created", "task_id": "42"}):
        res = client.post(
            "/api/v1/burp/trigger-scan",
            json={"api_url": "http://127.0.0.1:13337", "target_urls": ["http://example.com/test"]},
        )
        assert res.status_code == 200
        assert res.json()["task_id"] == "42"


def test_post_extension_push(client, test_db):
    target = Target(name="Test Target", base_url="http://example.com")
    test_db.add(target)
    test_db.commit()

    push_payload = {
        "target_id": target.id,
        "method": "GET",
        "url": "http://example.com/page?param=1",
        "headers": {"User-Agent": "Burp Extension"},
        "body": None,
        "response": {"body": "<html>test</html>"},
    }
    res = client.post("/api/v1/burp/extension-push", json=push_payload)
    assert res.status_code == 200
    assert res.json()["status"] == "success"


def test_send_to_repeater_and_queues(client, test_db):
    repeater_queue.clear()
    findings_queue.clear()

    target = Target(name="Test Target", base_url="http://example.com")
    test_db.add(target)
    test_db.commit()

    endpoint = Endpoint(target_id=target.id, url_pattern="http://example.com/profile", method="POST")
    test_db.add(endpoint)
    test_db.commit()

    param = Param(endpoint_id=endpoint.id, name="username", location="body")
    test_db.add(param)
    test_db.commit()

    finding = Finding(
        endpoint_id=endpoint.id,
        param_id=param.id,
        best_payload="<script>alert(1)</script>",
        severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
        poc_request={"url": "http://example.com/profile", "method": "POST", "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
    )
    test_db.add(finding)
    test_db.commit()

    # 1. Send to Repeater
    res = client.post("/api/v1/burp/send-to-repeater", json={"finding_id": finding.id, "tool": "repeater"})
    assert res.status_code == 200
    assert res.json()["status"] == "queued"

    # 2. Get Repeater Queue
    res = client.get("/api/v1/burp/repeater-queue")
    assert res.status_code == 200
    r_items = res.json()
    assert len(r_items) == 1
    assert r_items[0]["host"] == "example.com"

    # 3. Get Findings Queue
    res = client.get("/api/v1/burp/findings-queue")
    assert res.status_code == 200
    f_items = res.json()
    assert len(f_items) == 1
    assert "username" in f_items[0]["name"]


def test_scan_tasks_endpoints(client):
    with patch("backend_api.routers.burp.BurpService.get_scan_tasks", return_value=[{"id": "1", "status": "running"}]), \
         patch("backend_api.routers.burp.BurpService.get_scan_task", return_value={"id": "1", "status": "running", "progress": 50}), \
         patch("backend_api.routers.burp.BurpService.cancel_scan_task", return_value=True):

        # List tasks
        res = client.get("/api/v1/burp/scan-tasks?api_url=http://127.0.0.1:13337")
        assert res.status_code == 200
        assert len(res.json()) == 1

        # Get task details
        res = client.get("/api/v1/burp/scan-tasks/1?api_url=http://127.0.0.1:13337")
        assert res.status_code == 200
        assert res.json()["progress"] == 50

        # Cancel task
        res = client.delete("/api/v1/burp/scan-tasks/1?api_url=http://127.0.0.1:13337")
        assert res.status_code == 200
        assert res.json()["canceled"] is True


def test_issue_definitions(client):
    with patch("backend_api.routers.burp.BurpService.get_issue_definitions", return_value={"issues": [{"name": "XSS"}]}):
        res = client.get("/api/v1/burp/issue-definitions?api_url=http://127.0.0.1:13337")
        assert res.status_code == 200
        assert "issues" in res.json()


def test_collaborator_endpoints(client, test_db):
    active_collaborator_payloads.clear()

    # Register payload
    res = client.post("/api/v1/burp/collaborator-register", json={"payload": "canary.burpcollaborator.net"})
    assert res.status_code == 200
    assert res.json()["registered"] == "canary.burpcollaborator.net"

    # Get active payload
    res = client.get("/api/v1/burp/collaborator-payload")
    assert res.status_code == 200
    assert res.json()["payload"] == "canary.burpcollaborator.net"

    # Create test case for interaction callback
    target = Target(name="Test Target", base_url="http://example.com")
    test_db.add(target)
    test_db.commit()

    endpoint = Endpoint(target_id=target.id, url_pattern="http://example.com/search", method="GET")
    test_db.add(endpoint)
    test_db.commit()

    param = Param(endpoint_id=endpoint.id, name="q", location="query")
    test_db.add(param)
    test_db.commit()

    test_case = TestCase(
        experiment_id=1,
        endpoint_id=endpoint.id,
        param_id=param.id,
        token="tok_12345_unique",
        payload="<script src='//tok_12345_unique.canary.burpcollaborator.net'></script>",
    )
    test_db.add(test_case)
    test_db.commit()

    # Report interaction callback
    interaction = {
        "test_case_id": "tok_12345_unique",
        "type": "HTTP",
        "client_ip": "10.0.0.1",
        "timestamp": "2026-08-28 14:00:00",
        "request": base64.b64encode(b"GET / HTTP/1.1\r\nHost: tok_12345_unique.canary.burpcollaborator.net\r\n\r\n").decode("ascii"),
    }
    with patch("backend_api.services.burp_service.BurpService.auto_forward_finding"):
        res = client.post("/api/v1/burp/collaborator-interaction", json=interaction)
        assert res.status_code == 200
        assert res.json()["status"] == "created"
        finding_id = res.json()["finding_id"]
        assert finding_id > 0


def test_sitemap_bulk_push(client, test_db):
    target = Target(name="Bulk Target", base_url="http://example.com")
    test_db.add(target)
    test_db.commit()

    payload = {
        "target_id": target.id,
        "items": [
            {
                "method": "GET",
                "url": "http://example.com/api/v1/users?id=123",
                "headers": {"Accept": "application/json"},
                "response_body": "{\"user\":\"admin\"}",
                "status_code": 200,
            },
            {
                "method": "POST",
                "url": "http://example.com/api/v1/submit",
                "headers": {"Content-Type": "application/json"},
                "body": "{\"comment\":\"hello\"}",
                "response_body": "{\"status\":\"ok\"}",
                "status_code": 201,
            },
        ],
    }
    res = client.post("/api/v1/burp/sitemap-bulk-push", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["imported_count"] == 2
    assert data["total_processed"] == 2


def test_websocket_push(client, test_db):
    target = Target(name="WS Target", base_url="http://example.com")
    test_db.add(target)
    test_db.commit()

    payload = {
        "target_id": target.id,
        "url": "ws://example.com/chat/stream",
        "direction": "client_to_server",
        "payload": "{\"action\":\"join\",\"room\":\"lobby\"}",
        "is_binary": False,
    }
    res = client.post("/api/v1/burp/websocket-push", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert data["direction"] == "client_to_server"
    assert data["endpoint_id"] > 0


def test_collaborator_generate_and_list(client):
    active_collaborator_payloads.clear()
    
    # 1. Fallback generation when none registered
    res = client.post("/api/v1/burp/collaborator-generate", json={"test_case_id": "tc123", "prefix": "t"})
    assert res.status_code == 200
    assert "ttc123.oastify.com" in res.json()["canary"]

    # 2. Register base domain
    client.post("/api/v1/burp/collaborator-register", json={"payload": "custom-collab.oastify.com"})

    # 3. Dynamic canary per test case
    res = client.post("/api/v1/burp/collaborator-generate", json={"test_case_id": "test456", "prefix": "t"})
    assert res.status_code == 200
    assert res.json()["canary"] == "ttest456.custom-collab.oastify.com"

    # 4. List registered payloads
    res = client.get("/api/v1/burp/collaborator-payloads")
    assert res.status_code == 200
    assert "custom-collab.oastify.com" in res.json()["payloads"]


def test_session_status_endpoint(client):
    with patch("backend_api.services.burp_service.BurpService.check_session_health", return_value={"alive": True, "status_code": 200, "authenticated": True}):
        res = client.get("/api/v1/burp/session-status?target_url=http://example.com/dashboard")
        assert res.status_code == 200
        data = res.json()
        assert data["alive"] is True
        assert data["authenticated"] is True


def test_browser_workers_proxy_resolution():
    from browser_workers.executor import BrowserExecutor
    from backend_api.config import settings

    # Verify precedence independently of external DNS/network state.
    with patch("backend_api.utils.proxy_health.proxy_reachable", return_value=(True, None)), \
         patch.object(settings, "BURP_PROXY_WORKERS", False), \
         patch.object(settings, "PROXY_URL", "http://corporate-proxy:8080"):
        res = BrowserExecutor._resolve_proxy_server(rotated_proxy="http://rot-proxy:9090")
        assert res == {"server": "http://rot-proxy:9090"}

        res_norot = BrowserExecutor._resolve_proxy_server(rotated_proxy=None)
        assert res_norot == {"server": "http://corporate-proxy:8080"}

    # Burp worker proxy overrides
    with patch("backend_api.utils.proxy_health.proxy_reachable", return_value=(True, None)), \
         patch.object(settings, "BURP_PROXY_WORKERS", True), \
         patch.object(settings, "BURP_PROXY_URL", "http://127.0.0.1:8080"):
        res = BrowserExecutor._resolve_proxy_server(rotated_proxy="http://rot-proxy:9090")
        assert res == {"server": "http://127.0.0.1:8080"}

    # Unreachable proxies must fail open to direct network access rather than
    # passing a dead proxy to the browser worker.
    with patch("backend_api.utils.proxy_health.proxy_reachable", return_value=(False, "connection refused")), \
         patch.object(settings, "BURP_PROXY_WORKERS", False), \
         patch.object(settings, "PROXY_URL", "http://dead-proxy:8080"):
        res = BrowserExecutor._resolve_proxy_server(rotated_proxy="http://dead-rotated:9090")
        assert res is None

