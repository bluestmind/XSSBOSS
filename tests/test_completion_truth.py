"""Regression tests for honest run completion and audit telemetry."""
from datetime import UTC, datetime

from backend_api.models.endpoint import Endpoint
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.models.finding import Finding, FindingStatus, Severity
from backend_api.models.param import Param
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.models.target import Target, TargetStatus
from backend_api.services.run_state_service import RunStateService
from backend_api.services.result_service import ResultService


def _finished_miss_run(db_session):
    target = Target(
        name="Completion truth target",
        base_url="https://completion.test",
    )
    db_session.add(target)
    db_session.flush()
    endpoint = Endpoint(
        target_id=target.id,
        method="GET",
        url_pattern="https://completion.test/login?next=xssboss",
    )
    db_session.add(endpoint)
    db_session.flush()
    param = Param(endpoint_id=endpoint.id, name="next", location="query")
    db_session.add(param)
    db_session.flush()
    experiment = Experiment(
        target_id=target.id,
        name="Honest terminal run",
        strategy=ExperimentStrategy.SMART_ADAPTIVE,
        status=ExperimentStatus.RUNNING,
        limits={},
        started_at=datetime.now(UTC),
    )
    db_session.add(experiment)
    db_session.flush()
    test_case = TestCase(
        experiment_id=experiment.id,
        endpoint_id=endpoint.id,
        param_id=param.id,
        payload="https://example.com/xssboss-open-redirect",
        token="completion-truth-token",
        technique="open_redirect_absolute_url",
        research_metadata={"classification": "redirect_probe", "auditor": "open_redirect"},
        status=TestCaseStatus.COMPLETED,
    )
    db_session.add(test_case)
    db_session.flush()
    db_session.add(Execution(
        test_case_id=test_case.id,
        oracle_status=OracleStatus.MISSED,
        duration_ms=123,
        logs='{"final_url":"https://completion.test/login?next=xssboss"}',
    ))
    RunStateService.ensure_pipeline(db_session, experiment.id)
    db_session.commit()
    return target, experiment, test_case


def test_terminal_misses_complete_as_inconclusive_not_failed(db_session, monkeypatch):
    target, experiment, _ = _finished_miss_run(db_session)
    monkeypatch.setattr(
        "backend_api.services.campaign_report_service.CampaignReportService.generate_report",
        lambda *args, **kwargs: {},
    )

    from browser_workers.worker import _check_experiment_completion

    _check_experiment_completion(db_session, experiment.id)
    db_session.refresh(experiment)
    db_session.refresh(target)

    assert experiment.status == ExperimentStatus.COMPLETED
    assert experiment.limits["coverage"]["execution_plan_complete"] is True
    assert experiment.limits["coverage"]["trustworthy_clean"] is False
    assert experiment.limits["done"]["safe_claim"] is False
    assert target.status == TargetStatus.RECON_ONLY


def test_audit_reports_exact_payload_and_integration_truth(db_session):
    _, experiment, test_case = _finished_miss_run(db_session)

    from backend_api.routers.experiments import get_experiment_audit

    audit = get_experiment_audit(experiment.id, db_session)

    assert audit["verdict"]["state"] == "inconclusive_no_confirmed_vulnerability"
    assert audit["summary"]["test_cases"] == 1
    assert audit["summary"]["executions"] == 1
    assert audit["summary"]["distinct_payloads"] == 1
    assert audit["payload_inventory"][0]["payload"] == test_case.payload
    assert audit["payload_inventory"][0]["classification"] == "redirect_probe"
    assert audit["payload_inventory"][0]["outcomes"] == {"missed": 1}
    assert audit["integrations"]["burp"]["rest_used"] is False
    assert audit["integrations"]["burp"]["extension_used"] is False
    assert audit["integrations"]["browser"]["used"] is True


def test_live_browser_uses_saved_poc_and_requires_hit_evidence(db_session):
    _, _, test_case = _finished_miss_run(db_session)
    exact_url = "https://completion.test/login?next=%2Fdashboard%3Fproof%3D1"
    finding = Finding(
        endpoint_id=test_case.endpoint_id,
        param_id=test_case.param_id,
        vuln_type="xss",
        scanner_module="xss_fuzzer",
        best_payload="<script>alert(1)</script>",
        severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
        poc_request={"url": exact_url, "method": "GET"},
        evidence_refs={"test_case_id": test_case.id},
    )
    db_session.add(finding)
    db_session.commit()

    unverified = ResultService.enrich_finding(finding, db=db_session)
    assert unverified.poc_url == exact_url
    assert unverified.poc_source == "stored_request"
    assert unverified.is_verified is False
    assert unverified.verification_state == "unverified"
    assert unverified.browser_replay_available is True

    hit = Execution(
        test_case_id=test_case.id,
        oracle_status=OracleStatus.HIT,
        attempt_no=2,
        idempotency_key="completion-truth-hit",
    )
    db_session.add(hit)
    db_session.flush()
    finding.evidence_refs = {
        "test_case_id": test_case.id,
        "execution_ids": [hit.id],
    }
    db_session.commit()

    verified = ResultService.enrich_finding(finding, db=db_session)
    assert verified.is_verified is True
    assert verified.verification_state == "browser_confirmed"
