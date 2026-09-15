from backend_api.quality.accuracy import evaluate_accuracy, passes_accuracy_gate


def test_accuracy_gate_passes_complete_high_quality_results():
    truth = [
        {"slug": "v1", "expected_vulnerable": True},
        {"slug": "v2", "expected_vulnerable": True},
        {"slug": "safe", "expected_vulnerable": False},
    ]
    metrics = evaluate_accuracy(truth, [
        {"slug": "v1", "detected": True},
        {"slug": "v2", "detected": True},
        {"slug": "safe", "detected": False},
    ])
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert passes_accuracy_gate(metrics)


def test_accuracy_gate_fails_missing_or_false_positive_results():
    truth = [
        {"slug": "vulnerable", "expected_vulnerable": True},
        {"slug": "safe", "expected_vulnerable": False},
    ]
    missing = evaluate_accuracy(truth, [{"slug": "vulnerable", "detected": True}])
    false_positive = evaluate_accuracy(truth, [
        {"slug": "vulnerable", "detected": True},
        {"slug": "safe", "detected": True},
    ])
    assert not passes_accuracy_gate(missing)
    assert not passes_accuracy_gate(false_positive)


def test_cors_auditor_suppresses_preflight_only_false_positives():
    """Verify CorsAuditor drops preflight-only reflection when data request rejects CORS."""
    from backend_api.models.endpoint import Endpoint
    from backend_api.services.auditors.cors import CorsAuditor
    from unittest.mock import MagicMock, patch

    ep = Endpoint(id=1, method="POST", url_pattern="https://example.com/api/test")
    db = MagicMock()

    # Preflight returns ACAO + ACAC, but data POST returns 401 with CORS policy violation
    # This is a response-classification unit test. Do not let an operator's
    # optional proxy profile affect HTTP client construction (for example, a
    # SOCKS proxy when the optional socksio dependency is not installed).
    with patch(
        "backend_api.utils.stealth.get_http_proxy_kwargs", return_value={}
    ), patch("httpx.Client.request") as mock_req:
        options_resp = MagicMock(
            status_code=200,
            headers={
                "access-control-allow-origin": CorsAuditor.TEST_ORIGIN,
                "access-control-allow-credentials": "true",
            },
            text=""
        )
        data_resp = MagicMock(
            status_code=401,
            headers={},
            text='{"exceptionMessage": "CORS policy violation - origin not on allowlist"}'
        )
        mock_req.side_effect = [options_resp, data_resp]

        res = CorsAuditor._probe_endpoint(ep)
        assert res is None, "Expected preflight-only CORS reflection to be suppressed as false positive"
