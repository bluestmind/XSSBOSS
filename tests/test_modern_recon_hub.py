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
