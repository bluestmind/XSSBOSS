from backend_api.models.context import Context
from backend_api.models.endpoint import Endpoint
from backend_api.models.finding import Finding, FindingStatus, Severity
from backend_api.models.param import Param
from backend_api.models.sink import DetectedVia, Sink
from backend_api.models.target import Target
from backend_api.services.recon_dossier_service import ReconDossierService


def test_dossier_preserves_structure_redacts_secrets_and_routes_other_bugs(db_session):
    target = Target(name="Dossier Target", base_url="https://dossier.example")
    db_session.add(target)
    db_session.flush()
    endpoint = Endpoint(
        target_id=target.id,
        method="GET",
        url_pattern="https://dossier.example/api/fetch",
        sample_request_body='{"access_token":"json-secret-value","ok":1}',
        sample_response_body="<html>authorization=super-secret-value</html>",
    )
    db_session.add(endpoint)
    db_session.flush()
    url_param = Param(endpoint_id=endpoint.id, name="callback_url", location="query")
    id_param = Param(endpoint_id=endpoint.id, name="account_id", location="query")
    db_session.add_all([url_param, id_param])
    db_session.flush()
    context = Context(
        endpoint_id=endpoint.id,
        param_id=url_param.id,
        context_type="HTML_TEXT",
        snippet="<div>callback_url</div>",
    )
    db_session.add(context)
    db_session.flush()
    sink = Sink(
        context_id=context.id,
        sink_type="innerHTML",
        detected_via=DetectedVia.STATIC,
        taint_path=["callback_url", "innerHTML"],
    )
    db_session.add(sink)
    db_session.flush()
    db_session.add(Finding(
        endpoint_id=endpoint.id,
        param_id=url_param.id,
        context_id=context.id,
        sink_id=sink.id,
        vuln_type="xss",
        best_payload="<svg>",
        severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
        evidence_summary="execution oracle hit",
    ))
    db_session.flush()

    dossier = ReconDossierService.build(
        db_session,
        target.id,
        observations={
            "bundle": {"client_secret": "observation-secret", "secret_indicator_count": 2},
            "snippet": "api_key='bundle-secret-value'",
        },
    )

    assert dossier["summary"] == {
        "endpoints": 1,
        "parameters": 2,
        "contexts": 1,
        "sinks": 1,
        "findings": 1,
        "technologies": [],
        "bug_classes": len(dossier["coverage_matrix"]),
    }
    assert "super-secret-value" not in dossier["endpoints"][0]["response_excerpt"]
    assert "json-secret-value" not in dossier["endpoints"][0]["request_sample"]
    assert "[REDACTED]" in dossier["endpoints"][0]["response_excerpt"]
    assert dossier["recon_observations"]["bundle"] == {
        "client_secret": "[REDACTED]",
        "secret_indicator_count": 2,
    }
    assert "bundle-secret-value" not in dossier["recon_observations"]["snippet"]
    routes = dossier["endpoints"][0]["bug_class_routes"]
    assert routes["ssrf"][0]["param_id"] == url_param.id
    assert routes["open_redirect"][0]["param_id"] == url_param.id
    assert any(item["param_id"] == id_param.id for item in routes["sqli"])
    assert any(item["param_id"] == id_param.id for item in routes["idor_bola"])
    assert routes["client_secret_exposure"][0]["param_id"] is None
    assert dossier["coverage_matrix"]["xss"]["candidate_count"] == 2
    assert len(dossier["integrity_sha256"]) == 64


def test_recon_routing_prioritizes_candidates_without_dropping_coverage(db_session):
    target = Target(name="Routing Target", base_url="https://routing.example")
    db_session.add(target)
    db_session.flush()
    generic = Endpoint(target_id=target.id, method="GET", url_pattern="https://routing.example/health")
    candidate = Endpoint(target_id=target.id, method="POST", url_pattern="https://routing.example/import")
    db_session.add_all([generic, candidate])
    db_session.flush()
    db_session.add(Param(endpoint_id=candidate.id, name="webhook_url", location="json"))
    db_session.flush()

    dossier = ReconDossierService.build(db_session, target.id)
    ordered = ReconDossierService.prioritize_endpoints([generic, candidate], dossier, "ssrf")

    assert [endpoint.id for endpoint in ordered] == [candidate.id, generic.id]
    assert set(endpoint.id for endpoint in ordered) == {generic.id, candidate.id}
