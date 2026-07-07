"""Integration tests for native xssboss hunt pipeline."""
import os
import pytest
from unittest.mock import patch, MagicMock
from xssboss import hunt_internal
from backend_api.models.target import Target, TargetStatus
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.models.finding import Finding, Severity, FindingStatus

from backend_api.db.session import SessionLocal

@patch("recon_engine.crawler.Crawler.crawl")
@patch("backend_api.services.fuzzing_service.FuzzingService.run_experiment")
def test_hunt_pipeline_end_to_end(mock_run_exp, mock_crawl):
    db_session = SessionLocal()
    # Setup test target
    target = Target(
        name="Hunt Test Target",
        base_url="https://hunttest.example.com",
        status=TargetStatus.RECON_ONLY
    )
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)

    # Setup discovered endpoint & finding
    ep = Endpoint(target_id=target.id, url_pattern="https://hunttest.example.com/search?q=", method="GET")
    db_session.add(ep)
    db_session.commit()
    db_session.refresh(ep)

    param = Param(endpoint_id=ep.id, name="q", location="query")
    db_session.add(param)
    db_session.commit()
    db_session.refresh(param)

    finding = Finding(
        endpoint_id=ep.id,
        param_id=param.id,
        vuln_type="reflected_xss",
        scanner_module="native_hunt",
        confidence="firm",
        severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
        best_payload='q=<script>alert(1)</script>',
        evidence_summary="Verified execution of alert(1)",
        report_text="Sample report"
    )
    db_session.add(finding)
    db_session.commit()

    # Run hunt_internal
    hunt_internal(
        target_id=target.id,
        url=None,
        name=None,
        max_pages=2,
        strategy="quick_light",
        auto_report=True
    )

    # Verify crawl was invoked
    mock_crawl.assert_called_once()
    # Verify experiment was launched
    mock_run_exp.assert_called_once()

    # Verify reports generated
    md_path = f"reports/hunt_finding_{finding.id}_reflected_xss.md"
    poc_path = f"reports/hunt_poc_{finding.id}_reflected_xss.html"
    assert os.path.exists(md_path)
    assert os.path.exists(poc_path)

    # Clean up generated files
    if os.path.exists(md_path):
        os.remove(md_path)
    if os.path.exists(poc_path):
        os.remove(poc_path)
