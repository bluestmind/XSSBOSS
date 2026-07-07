"""Unit tests for CRLFInjectionAuditor."""
import unittest
from unittest.mock import MagicMock, patch
import httpx

from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.finding import Severity
from backend_api.services.auditors.crlf_injection import CRLFInjectionAuditor


class TestCRLFInjectionAuditor(unittest.TestCase):

    def test_candidate_params(self):
        self.assertIn("redirect", CRLFInjectionAuditor.CANDIDATE_PARAMS)
        self.assertIn("url", CRLFInjectionAuditor.CANDIDATE_PARAMS)
        self.assertIn("lang", CRLFInjectionAuditor.CANDIDATE_PARAMS)

    @patch("httpx.Client.request")
    def test_header_injection_detected(self, mock_request):
        """Header injection is detected when custom canary header reflects in response headers."""
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "/home", "X-XSSBoss-Injected": "canary_header_ok"}
        mock_resp.text = ""
        mock_request.return_value = mock_resp

        ep = Endpoint(id=1, url_pattern="https://example.com/redirect", method="GET")
        param = Param(id=1, endpoint_id=1, name="url", location="query")
        ep.params = [param]

        db = MagicMock()
        findings = CRLFInjectionAuditor.audit_endpoints(db, [ep])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "header_injection")

    @patch("httpx.Client.request")
    def test_response_splitting_detected(self, mock_request):
        """Double CRLF injecting HTML into the response body is flagged as response splitting XSS."""
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.text = "HTTP/1.1 200 OK\r\n\r\n<svg/onload=__XSS__('crlf_split')>"
        mock_request.return_value = mock_resp

        ep = Endpoint(id=1, url_pattern="https://example.com/set-lang", method="GET")
        param = Param(id=1, endpoint_id=1, name="lang", location="query")
        ep.params = [param]

        db = MagicMock()
        findings = CRLFInjectionAuditor.audit_endpoints(db, [ep])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "response_splitting_xss")
        self.assertEqual(findings[0].severity, Severity.HIGH)


if __name__ == "__main__":
    unittest.main()
