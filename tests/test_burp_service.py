import unittest

import httpx

from backend_api.services.burp_service import BurpService


def response(status_code, text="{}", url="http://127.0.0.1:1337/v0.1/scan"):
    request = httpx.Request("GET", url)
    return httpx.Response(status_code, text=text, request=request)


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class BurpServiceUrlTests(unittest.TestCase):
    def test_build_url_uses_header_auth_route_when_api_key_is_present(self):
        url = BurpService._build_url("http://127.0.0.1:1337", "secret", "scan")

        self.assertEqual(url, "http://127.0.0.1:1337/v0.1/scan")

    def test_build_url_strips_legacy_key_version_suffix_from_user_input(self):
        url = BurpService._build_url("http://127.0.0.1:1337/secret/v1", "secret", "/scan")

        self.assertEqual(url, "http://127.0.0.1:1337/v0.1/scan")

    def test_request_burp_retries_legacy_key_in_path_after_auth_failure(self):
        client = FakeClient([
            response(401, '{"error":"Unauthorized"}'),
            response(200, '{"tasks":[]}'),
        ])

        resp, url = BurpService._request_burp(client, "GET", "http://127.0.0.1:1337", "secret", "scan")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(url, "http://127.0.0.1:1337/secret/v0.1/scan")
        self.assertEqual(
            [call[1] for call in client.calls],
            [
                "http://127.0.0.1:1337/v0.1/scan",
                "http://127.0.0.1:1337/secret/v0.1/scan",
            ],
        )

    def test_request_burp_retries_plain_http_for_local_ssl_eof(self):
        client = FakeClient([
            httpx.ConnectError("[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol"),
            response(200, '{"tasks":[]}', "http://127.0.0.1:13337/v0.1/scan"),
        ])

        resp, url = BurpService._request_burp(client, "GET", "https://127.0.0.1:13337", None, "scan")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(url, "http://127.0.0.1:13337/v0.1/scan")
        self.assertEqual(
            [call[1] for call in client.calls],
            [
                "https://127.0.0.1:13337/v0.1/scan",
                "http://127.0.0.1:13337/v0.1/scan",
            ],
        )

    def test_import_from_rest_requires_task_id(self):
        with self.assertRaisesRegex(ValueError, "task ID"):
            BurpService.import_from_rest(None, 1, "http://127.0.0.1:13337")

    def test_import_from_rest_rejects_url_as_task_id(self):
        with self.assertRaisesRegex(ValueError, "contains a URL"):
            BurpService.import_from_rest(
                None,
                1,
                "http://127.0.0.1:13337",
                task_id="http://127.0.0.1:13337",
            )

    def test_auto_forward_finding_populates_repeater_and_findings_queues(self):
        from backend_api.routers.burp import repeater_queue, findings_queue
        # Reset queues
        repeater_queue.clear()
        findings_queue.clear()

        # Mock objects
        class MockParam:
            def __init__(self):
                self.name = "test_param"
                self.location = "query"

        class MockEndpoint:
            def __init__(self):
                self.url_pattern = "http://example.com/api/test"
                self.method = "GET"
                self.auth_context = {"Cookie": "session=123"}
                self.sample_request_body = {}

        class MockFinding:
            def __init__(self):
                self.id = 999
                self.best_payload = "'; alert(1)//"
                self.severity = "high"
                self.poc_request = {
                    "url": "http://example.com/api/test?test_param='; alert(1)//",
                    "method": "GET",
                    "headers": {"Cookie": "session=123"}
                }
                self.poc_html = "<html><body>POC</body></html>"
                self.evidence_refs = {
                    "sink_details": {
                        "sink_type": "innerHTML",
                        "js_location": "app.js:45",
                        "notes": "dynamic trace verified"
                    }
                }
                self.report_text = "Standard Reflected XSS verified"
                self.endpoint = MockEndpoint()
                self.param = MockParam()

        finding = MockFinding()
        BurpService.auto_forward_finding(None, finding)

        self.assertEqual(len(repeater_queue), 1)
        self.assertEqual(len(findings_queue), 1)
        
        self.assertEqual(repeater_queue[0]["host"], "example.com")
        self.assertEqual(repeater_queue[0]["secure"], False)
        self.assertIn("GET /api/test?test_param='; alert(1)// HTTP/1.1", repeater_queue[0]["raw_request"])
        self.assertIn("Cookie: session=123", repeater_queue[0]["raw_request"])
        self.assertEqual(repeater_queue[0]["label"], "Auto-XSSBoss 999 (test_param)")

        self.assertEqual(findings_queue[0]["id"], 999)
        self.assertEqual(findings_queue[0]["name"], "XSS Boss: Verified XSS (query parameter 'test_param')")
        self.assertEqual(findings_queue[0]["severity"], "high")
        self.assertEqual(findings_queue[0]["sink_type"], "innerHTML")
        self.assertEqual(findings_queue[0]["js_location"], "app.js:45")


class BurpCollaboratorTests(unittest.TestCase):
    def test_register_collaborator(self):
        from backend_api.routers.burp import register_collaborator, active_collaborator_payloads
        active_collaborator_payloads.clear()
        
        res = register_collaborator({"payload": "example.oastify.com"})
        self.assertEqual(res["status"], "ok")
        self.assertEqual(active_collaborator_payloads, ["example.oastify.com"])
        
    def test_report_collaborator_interaction_success(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from backend_api.models.base import BaseModel
        from backend_api.models.test_case import TestCase
        from backend_api.models.endpoint import Endpoint
        from backend_api.models.param import Param
        from backend_api.routers.burp import report_collaborator_interaction
        
        # Setup in-memory DB
        engine = create_engine("sqlite:///:memory:")
        BaseModel.metadata.create_all(engine)
        SessionLocal = sessionmaker(bind=engine)
        db = SessionLocal()
        
        try:
            # Create endpoint, param, test case
            endpoint = Endpoint(target_id=1, url_pattern="http://test.com/api", method="GET")
            db.add(endpoint)
            db.flush()
            
            param = Param(endpoint_id=endpoint.id, name="q", location="query")
            db.add(param)
            db.flush()
            
            test_case = TestCase(
                experiment_id=1,
                endpoint_id=endpoint.id,
                param_id=param.id,
                payload="<script src='http://tTOKEN.oastify.com'></script>",
                token="my_test_unique_token_123456"
            )
            db.add(test_case)
            db.commit()
            
            # Send reported interaction matching the token
            interaction_data = {
                "test_case_id": "my_test_unique_token_123456",
                "type": "HTTP",
                "client_ip": "192.168.1.50",
                "timestamp": "2026-06-13 12:00:00",
                "request": "R0VUIC8gSFRUUC8xLjE=" # "GET / HTTP/1.1" base64
            }
            
            res = report_collaborator_interaction(interaction_data, db=db)
            self.assertEqual(res["status"], "created")
            
            # Verify finding and execution in DB
            from backend_api.models.finding import Finding
            from backend_api.models.execution import Execution
            
            finding = db.query(Finding).filter(Finding.endpoint_id == endpoint.id).first()
            self.assertIsNotNone(finding)
            self.assertEqual(finding.status, "confirmed")
            self.assertEqual(finding.severity, "critical")
            
            execution = db.query(Execution).filter(Execution.test_case_id == test_case.id).first()
            self.assertIsNotNone(execution)
            self.assertIn("GET / HTTP/1.1", execution.logs)
            
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
