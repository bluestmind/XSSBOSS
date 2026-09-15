"""Test suite for HackerOne Scraper Service, API, and Target Synchronization."""
from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend_api.main import app
from backend_api.db.session import get_db
from backend_api.models.base import BaseModel
from backend_api.models.target import Target
from backend_api.services.hackerone_scraper_service import HackerOneScraperService

# Setup in-memory sqlite DB for test isolation
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
BaseModel.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def sample_h1_raw():
    return [
        {
            "id": 101,
            "name": "Test Bounty Program",
            "handle": "test_bbp",
            "url": "https://hackerone.com/test_bbp",
            "website": "https://test.com",
            "offers_bounties": True,
            "offers_swag": False,
            "submission_state": "open",
            "targets": {
                "in_scope": [
                    {
                        "asset_identifier": "https://api.test.com",
                        "asset_type": "URL",
                        "eligible_for_bounty": True,
                        "max_severity": "critical"
                    },
                    {
                        "asset_identifier": "*.test.com",
                        "asset_type": "WILDCARD",
                        "eligible_for_bounty": True,
                        "max_severity": "high"
                    }
                ],
                "out_of_scope": [
                    {
                        "asset_identifier": "internal.test.com",
                        "asset_type": "DOMAIN"
                    }
                ]
            }
        },
        {
            "id": 102,
            "name": "Test VDP Program",
            "handle": "test_vdp",
            "url": "https://hackerone.com/test_vdp",
            "website": "https://vdp.com",
            "offers_bounties": False,
            "submission_state": "open",
            "targets": {
                "in_scope": [
                    {
                        "asset_identifier": "https://vdp.com",
                        "asset_type": "URL",
                        "eligible_for_bounty": False
                    }
                ],
                "out_of_scope": []
            }
        }
    ]


def test_fetch_all_programs(sample_h1_raw):
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = sample_h1_raw
        mock_get.return_value = mock_resp

        # 1. Fetch all
        all_progs = HackerOneScraperService.fetch_all_programs()
        assert len(all_progs) == 2

        # 2. Bounty only
        bounty_progs = HackerOneScraperService.fetch_all_programs(bounty_only=True)
        assert len(bounty_progs) == 1
        assert bounty_progs[0]["handle"] == "test_bbp"
        assert bounty_progs[0]["in_scope_count"] == 2
        assert bounty_progs[0]["out_of_scope_count"] == 1
        assert bounty_progs[0]["primary_url"] == "https://api.test.com"

        # 3. Query filter
        q_progs = HackerOneScraperService.fetch_all_programs(query="vdp")
        assert len(q_progs) == 1
        assert q_progs[0]["handle"] == "test_vdp"


def test_fetch_program_by_handle(sample_h1_raw):
    with patch("httpx.Client.get") as mock_get:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = sample_h1_raw
        mock_get.return_value = mock_resp

        prog = HackerOneScraperService.fetch_program_by_handle("test_bbp")
        assert prog is not None
        assert prog["name"] == "Test Bounty Program"
        assert len(prog["in_scope"]) == 2


def test_import_and_sync_target(sample_h1_raw):
    db = TestingSessionLocal()
    try:
        with patch("httpx.Client.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = sample_h1_raw
            mock_get.return_value = mock_resp

            # Bulk sync
            res = HackerOneScraperService.bulk_sync_to_database(db=db, handles=["test_bbp"])
            assert res["status"] == "success"
            assert res["imported_count"] == 1

            # Verify in DB
            target = db.query(Target).filter(Target.name == "Test Bounty Program").first()
            assert target is not None
            assert target.bounty_platform == "hackerone"
            assert target.base_url == "https://api.test.com"
            assert target.scope_tags["handle"] == "test_bbp"
            assert len(target.scope_tags["in_scope"]) == 2
            assert len(target.scope_tags["out_of_scope"]) == 1
    finally:
        db.close()


def test_export_programs(sample_h1_raw):
    programs = [
        {
            "name": "Test",
            "handle": "test",
            "url": "https://hackerone.com/test",
            "website": "https://test.com",
            "offers_bounties": True,
            "submission_state": "open",
            "primary_url": "https://test.com",
            "in_scope_count": 5,
            "out_of_scope_count": 1,
            "web_targets": ["https://test.com"]
        }
    ]
    # JSON export
    json_out = HackerOneScraperService.export_programs(programs, export_format="json")
    assert '"handle": "test"' in json_out

    # CSV export
    csv_out = HackerOneScraperService.export_programs(programs, export_format="csv")
    assert "Handle" in csv_out
    assert "test" in csv_out


def test_hackerone_api_endpoints(client):
    mock_prog = {
        "name": "Test Bounty Program",
        "handle": "test_bbp",
        "url": "https://hackerone.com/test_bbp",
        "website": "https://test.com",
        "offers_bounties": True,
        "submission_state": "open",
        "primary_url": "https://api.test.com",
        "in_scope_count": 2,
        "out_of_scope_count": 1,
        "in_scope": [{"asset_identifier": "https://api.test.com", "asset_type": "URL"}],
        "out_of_scope": [{"asset_identifier": "internal.test.com", "asset_type": "DOMAIN"}],
        "web_targets": ["https://api.test.com"]
    }

    with patch.object(HackerOneScraperService, "fetch_all_programs", return_value=[mock_prog]), \
         patch.object(HackerOneScraperService, "fetch_program_by_handle", return_value=mock_prog), \
         patch.object(HackerOneScraperService, "bulk_sync_to_database", return_value={"status": "success", "imported_count": 1, "targets": [{"target_id": 1, "name": "Test Bounty Program", "handle": "test_bbp"}]}):

        # 1. GET /api/v1/hackerone/programs
        res = client.get("/api/v1/hackerone/programs?bounty_only=true")
        assert res.status_code == 200
        assert res.json()["status"] == "success"
        assert res.json()["count"] == 1

        # 2. GET /api/v1/hackerone/programs/{handle}
        res = client.get("/api/v1/hackerone/programs/test_bbp")
        assert res.status_code == 200
        assert res.json()["program"]["name"] == "Test Bounty Program"

        # 3. POST /api/v1/hackerone/sync
        res = client.post("/api/v1/hackerone/sync", json={"handles": ["test_bbp"]})
        assert res.status_code == 200
        assert res.json()["status"] == "success"

        # 4. POST /api/v1/hackerone/export
        res = client.post("/api/v1/hackerone/export", json={"bounty_only": False, "format": "json"})
        assert res.status_code == 200

