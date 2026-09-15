"""Tests for HttpParamPollutionAuditor."""
import unittest
from unittest.mock import MagicMock, patch

from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.services.auditors.http_param import HttpParamPollutionAuditor


class TestHttpParamPollutionAuditor(unittest.TestCase):

    def test_audit_endpoints_detects_reflection(self):
        db = MagicMock()
        db.query().filter().filter().filter().first.return_value = None

        param = Param(id=10, endpoint_id=1, name="q", location="query")
        endpoint = Endpoint(
            id=1,
            target_id=1,
            method="GET",
            url_pattern="https://example.com/search",
            params=[param],
            auth_context={},
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Results for first_q and second_q"

        with patch("backend_api.services.auditors.http_param.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_resp
            findings = HttpParamPollutionAuditor.audit_endpoints(db, [endpoint])

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vuln_type, "http_parameter_pollution")

    def test_audit_endpoints_ignores_safe_endpoints(self):
        db = MagicMock()
        param = Param(id=11, endpoint_id=2, name="id", location="query")
        endpoint = Endpoint(
            id=2,
            target_id=1,
            method="GET",
            url_pattern="https://example.com/item",
            params=[param],
            auth_context={},
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Item details page without any parameter values"

        with patch("backend_api.services.auditors.http_param.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_resp
            findings = HttpParamPollutionAuditor.audit_endpoints(db, [endpoint])

        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
