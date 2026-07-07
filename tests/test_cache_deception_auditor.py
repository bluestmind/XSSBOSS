"""Unit tests for CacheDeceptionAuditor."""
import unittest
from unittest.mock import MagicMock, patch
import httpx

from backend_api.models.endpoint import Endpoint
from backend_api.services.auditors.cache_deception import CacheDeceptionAuditor


class TestCacheDeceptionAuditor(unittest.TestCase):

    @patch("httpx.Client.get")
    def test_cache_deception_detected(self, mock_get):
        """Path-confused static suffix returning public cache headers on dynamic endpoint is flagged."""
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "public, max-age=86400",
            "CF-Cache-Status": "HIT"
        }
        mock_resp.text = "<html><body><h1>User Account Dashboard</h1><div>Email: user@example.com</div></body></html>"
        mock_get.return_value = mock_resp

        ep = Endpoint(id=1, url_pattern="https://example.com/account/settings", method="GET")

        db = MagicMock()
        findings = CacheDeceptionAuditor.audit_endpoints(db, [ep])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "web_cache_deception")


if __name__ == "__main__":
    unittest.main()
