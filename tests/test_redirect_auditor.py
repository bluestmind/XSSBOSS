"""Tests for RedirectAuditor."""
import pytest
from unittest.mock import MagicMock, patch
from backend_api.services.auditors.redirect import RedirectAuditor
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.finding import FindingStatus, Severity

def test_redirect_candidate_params():
    assert "url" in RedirectAuditor.CANDIDATE_PARAMS
    assert "redirect" in RedirectAuditor.CANDIDATE_PARAMS
    assert "return_to" in RedirectAuditor.CANDIDATE_PARAMS
    assert "nocache" in RedirectAuditor.CANDIDATE_PARAMS

@patch.object(RedirectAuditor, "_test_payload")
def test_redirect_auditor_creates_finding(mock_test):
    mock_test.return_value = {
        "type": "header_redirect",
        "location": "https://xssboss.invalid/redirect-canary",
        "status_code": 302
    }

    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = None

    ep = Endpoint(id=1, url_pattern="https://example.com/redirect?url=", method="GET")
    param = Param(id=10, endpoint_id=1, name="url", location="query")
    ep.params = [param]

    findings = RedirectAuditor.audit_endpoints(db, [ep], limit=10)
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_type == "open_redirect"
    assert f.status == FindingStatus.CONFIRMED
    assert f.severity == Severity.MEDIUM
    assert "redirect-canary" in f.best_payload


def test_relative_redirect_with_canary_in_query_rejected():
    """Verify that relative redirects like /login?next=https://xssboss.invalid are not false positives."""
    ep = Endpoint(id=1, url_pattern="https://example.com/login?next=", method="GET")
    param = Param(id=10, endpoint_id=1, name="next", location="query")

    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock(
            status_code=302,
            headers={"Location": "/auth/login?next=https%3A%2F%2Fxssboss.invalid%2Fredirect-canary"},
            text=""
        )
        mock_get.return_value = mock_resp
        res = RedirectAuditor._test_payload(ep, param, "https://xssboss.invalid/redirect-canary")
        assert res is None, "Relative redirect containing canary in query string should not be marked as open redirect"

