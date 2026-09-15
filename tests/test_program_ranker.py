"""Program prioritization + dashboard endpoints (ranked list, profile, one-click hunt)."""
import pytest
from fastapi import BackgroundTasks
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend_api.models.base import BaseModel
from backend_api.models.target import Target, TargetStatus
from backend_api.services.program_scope import ProgramScope
from backend_api.services.program_ranker import ProgramRanker
from backend_api.routers import programs as programs_router


def _tags(handle, bounties, assets, submission="open"):
    return {"handle": handle, "offers_bounties": bounties, "submission_state": submission, "in_scope": assets}


BIG_BOUNTY = _tags("acme_bbp", True, [
    {"asset_identifier": "*.acme.com", "asset_type": "WILDCARD", "eligible_for_bounty": True, "max_severity": "critical"},
    {"asset_identifier": "api.acme.com", "asset_type": "URL", "eligible_for_bounty": True, "max_severity": "high"},
    {"asset_identifier": "shop.acme.com", "asset_type": "URL", "eligible_for_bounty": True, "max_severity": "high"},
])
SMALL_VDP = _tags("charity_vdp", False, [
    {"asset_identifier": "www.charity.org", "asset_type": "URL", "eligible_for_bounty": False, "max_severity": "low"},
])


# --------------------------------------------------------------------- scoring

def test_bounty_program_outranks_vdp():
    big = ProgramRanker.score(ProgramScope.from_scope_tags(BIG_BOUNTY))
    small = ProgramRanker.score(ProgramScope.from_scope_tags(SMALL_VDP))
    assert big.priority_score > small.priority_score
    assert big.offers_bounties and not small.offers_bounties


def test_score_rewards_surface_severity_and_wildcards():
    r = ProgramRanker.score(ProgramScope.from_scope_tags(BIG_BOUNTY))
    assert r.bounty_eligible_count == 3
    assert r.wildcard_count == 1
    assert r.top_severity == "critical"
    assert any("cash" in x for x in r.reasons)
    assert any("wildcard" in x for x in r.reasons)


def test_closed_submission_is_penalized():
    open_tags = _tags("p", True, BIG_BOUNTY["in_scope"], submission="open")
    closed_tags = _tags("p", True, BIG_BOUNTY["in_scope"], submission="paused")
    op = ProgramRanker.score(ProgramScope.from_scope_tags(open_tags),
                             submission_open=True)
    cl = ProgramRanker.score(ProgramScope.from_scope_tags(closed_tags),
                             submission_open=False)
    assert cl.priority_score < op.priority_score
    assert any("not open" in x for x in cl.reasons)


def test_rank_targets_sorts_best_first():
    class T:
        def __init__(self, id, name, tags):
            self.id, self.name, self.scope_tags = id, name, tags
    ranks = ProgramRanker.rank_targets([T(1, "charity", SMALL_VDP), T(2, "acme", BIG_BOUNTY)])
    assert [r.target_id for r in ranks] == [2, 1]  # bounty program first


# ---------------------------------------------------------------- endpoints

@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    BaseModel.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add_all([
        Target(tenant_id=1, name="Acme", base_url="https://acme.com", bounty_platform="hackerone",
               scope_tags=BIG_BOUNTY, status=TargetStatus.RECON_ONLY),
        Target(tenant_id=1, name="Charity", base_url="https://charity.org", bounty_platform="hackerone",
               scope_tags=SMALL_VDP, status=TargetStatus.RECON_ONLY),
    ])
    session.commit()
    yield session
    session.close()


def test_list_programs_ranked(db):
    res = programs_router.list_programs(limit=50, bounty_only=False, query=None, db=db)
    assert res["count"] == 2
    assert res["programs"][0]["name"] == "Acme"          # best first
    assert res["programs"][0]["run_status"] == "idle"


def test_list_programs_bounty_only(db):
    res = programs_router.list_programs(limit=50, bounty_only=True, query=None, db=db)
    assert {p["name"] for p in res["programs"]} == {"Acme"}


def test_program_profile_returns_worklist(db):
    target = db.query(Target).filter(Target.name == "Acme").first()
    prof = programs_router.program_profile(target_id=target.id, db=db)
    assert prof["rank"]["offers_bounties"] is True
    assert prof["summary"]["web_assets"] == 3
    assert prof["worklist"][0]["host"] == "acme.com"      # critical wildcard first
    assert prof["run"]["status"] == "idle"


def test_one_click_hunt_queues_and_reports_status(db):
    target = db.query(Target).filter(Target.name == "Acme").first()
    programs_router._program_runs.pop(target.id, None)
    bg = BackgroundTasks()
    res = programs_router.start_program_hunt(
        target_id=target.id, background_tasks=bg, max_assets=5, budget=500, strategy="quick_light", db=db
    )
    assert res["status"] == "queued"
    assert len(bg.tasks) == 1                              # background hunt scheduled
    status = programs_router.program_hunt_status(target_id=target.id)
    assert status["status"] == "queued"
    # A second start while queued is rejected.
    with pytest.raises(Exception):
        programs_router.start_program_hunt(
            target_id=target.id, background_tasks=BackgroundTasks(), max_assets=5, budget=500,
            strategy="quick_light", db=db
        )
