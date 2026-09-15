"""Unit tests for ModernReconHub unified orchestrator."""
import pytest
from backend_api.db.base import init_db, SessionLocal
from backend_api.models.target import Target, TargetStatus
from backend_api.models.endpoint import Endpoint
from recon_engine.modern_recon_hub import ModernReconHub


@pytest.fixture
def db_session():
    init_db()
    session = SessionLocal()
    yield session
    session.close()


def test_modern_recon_hub_pipeline(db_session):
    """Test full recon hub execution with synthetic target and HTML payload."""
    # 1. Create temporary target
    target = Target(name="ReconTestApp", base_url="https://recon-test.local", status=TargetStatus.RECON_ONLY)
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)

    sample_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <script>
        window.__remixManifest = {
            "routes": {
                "routes/admin": { "id": "routes/admin", "path": "admin/settings" }
            }
        };
        </script>
    </head>
    <body>
        <script>
        self.__next_f.push([1, "1:[\"$\",\"div\",null,{\"data-url\":\"/api/v1/user/account\"}]"]);
        </script>
    </body>
    </html>
    """

    hub = ModernReconHub(db_session, target_id=target.id, timeout=2.0)
    summary = hub.run_full_recon(html_content=sample_html, probe_remote=False)

    assert summary.target_id == target.id
    assert summary.total_endpoints_imported >= 1

    # Verify endpoints persisted in DB
    endpoints = db_session.query(Endpoint).filter(Endpoint.target_id == target.id).all()
    assert len(endpoints) >= 1
    assert any("/admin/settings" in ep.url_pattern or "/api/v1/user/account" in ep.url_pattern for ep in endpoints)


def test_modern_recon_hub_fetches_entry_html_and_preserves_bundle_evidence(db_session, monkeypatch):
    target = Target(name="BundleRecon", base_url="https://bundle-recon.local", status=TargetStatus.RECON_ONLY)
    db_session.add(target)
    db_session.commit()

    html = b'<html><div id="appConfig"></div><script src="/assets/app.js"></script></html>'
    javascript = b'''
        const value = new URLSearchParams(location.search).get('name');
        element.innerHTML = value;
        const appConfig = window.appConfig;
        window.location = appConfig;
        fetch("/api/v1/users");
    '''

    hub = ModernReconHub(db_session, target_id=target.id, timeout=2.0)
    def fake_fetch(url, **_kwargs):
        body = html if url == target.base_url else javascript
        content_type = "text/html" if url == target.base_url else "text/javascript"
        return body, url, 200, {"content-type": content_type}

    monkeypatch.setattr(hub, "_fetch_bounded", fake_fetch)
    monkeypatch.setattr(hub, "_run_framework_harvest", lambda *_args: [])
    monkeypatch.setattr(hub, "_run_api_discovery", lambda *_args: [])

    summary = hub.run_full_recon()

    assert summary.details["initial_document"]["source"] == "fetched"
    assert summary.discovered_sinks_count == 1
    assert summary.details["client_bundles"][0]["counts"]["dom_sinks"] == 1
    assert summary.details["client_bundles"][0]["discovered_parameters"] == ["name"]
    assert summary.details["client_bundles"][0]["counts"]["dom_clobbering_chain"] == 1
    endpoints = db_session.query(Endpoint).filter(Endpoint.target_id == target.id).all()
    assert any(endpoint.url_pattern.endswith("/api/v1/users") for endpoint in endpoints)


def test_modern_recon_hub_exports_research_ready_bounded_boundary_signals(
    db_session, monkeypatch
):
    target = Target(
        name="BoundaryBundleRecon",
        base_url="https://boundary-bundle.local",
        status=TargetStatus.RECON_ONLY,
    )
    db_session.add(target)
    db_session.commit()

    categories = (
        "sanitizer_context_mismatch",
        "sanitizer_output_invalidated",
        "sanitizer_partial_coverage",
        "opaque_sanitizer_flow",
        "trusted_types_unvalidated_flow",
        "effective_sanitizer_boundary",
    )
    findings = [
        {"category": categories[index % len(categories)], "source_param": str(index)}
        for index in range(125)
    ]
    findings[0]["raw_snippet"] = "private-source-text"
    analysis = {
        "url": "https://boundary-bundle.local/assets/app.js",
        "internal_api_endpoints": [],
        "discovered_parameters": [],
        "reachable_params": [],
        "sanitizer_boundary_findings": findings,
        "sanitizer_boundary_summary": {category: 125 for category in categories},
    }

    monkeypatch.setattr(
        "recon_engine.modern_recon_hub.BundleAnalyzer.analyze_script_content",
        lambda *_args, **_kwargs: analysis,
    )
    hub = ModernReconHub(db_session, target_id=target.id, timeout=2.0)
    monkeypatch.setattr(
        hub,
        "_fetch_bounded",
        lambda url, **_kwargs: (b"const x = 1", url, 200, {}),
    )
    monkeypatch.setattr(hub, "_run_framework_harvest", lambda *_args: [])
    monkeypatch.setattr(hub, "_run_api_discovery", lambda *_args: [])

    summary = hub.run_full_recon(
        html_content='<script src="/assets/app.js"></script>',
        probe_remote=False,
    )

    signal = summary.details["client_bundles"][0]
    assert signal["kind"] == "client_bundle"
    assert len(signal["sanitizer_boundary_findings"]) == 100
    assert signal["sanitizer_boundary_findings"][0] == {
        "category": findings[0]["category"],
        "source_param": findings[0]["source_param"],
    }
    assert "private-source-text" not in str(signal)
    assert signal["counts"]["sanitizer_boundary_findings"] == 100
    assert all(signal["counts"][category] == 100 for category in categories)
