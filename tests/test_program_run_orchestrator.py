"""Program-run orchestrator: priority, budget, per-asset isolation, and stop conditions."""
import pytest

from backend_api.services.program_scope import ProgramScope
from backend_api.services.program_run_orchestrator import (
    AssetOutcome,
    ProgramRunOrchestrator,
    RunBudget,
)

TAGS = {
    "handle": "acme",
    "offers_bounties": True,
    "in_scope": [
        {"asset_identifier": "a.com", "asset_type": "DOMAIN", "eligible_for_bounty": True, "max_severity": "critical"},
        {"asset_identifier": "b.com", "asset_type": "DOMAIN", "eligible_for_bounty": True, "max_severity": "high"},
        {"asset_identifier": "c.com", "asset_type": "DOMAIN", "eligible_for_bounty": False, "max_severity": "low"},
    ],
}


def _scope():
    return ProgramScope.from_scope_tags(TAGS)


def _fn(results=None, record=None, raise_on=None):
    """Build a hunt_asset_fn returning per-host results and recording (host, cap)."""
    results = results or {}
    def fn(asset, cap):
        if record is not None:
            record.append((asset.host, cap))
        if raise_on and asset.host == raise_on:
            raise RuntimeError("asset boom")
        return results.get(asset.host, {"endpoints": 3, "findings": 0, "requests_used": 10})
    return fn


# --------------------------------------------------------------------- priority

def test_hunts_in_priority_order():
    rec = []
    ProgramRunOrchestrator.run(_scope(), _fn(record=rec), RunBudget(max_requests_total=10_000))
    assert [h for h, _ in rec] == ["a.com", "b.com", "c.com"]


def test_max_assets_caps_the_run():
    rec = []
    ProgramRunOrchestrator.run(_scope(), _fn(record=rec), RunBudget(max_assets=2, max_requests_total=10_000))
    assert [h for h, _ in rec] == ["a.com", "b.com"]


# --------------------------------------------------------------------- budget

def test_request_budget_exhaustion_stops_and_marks_rest():
    fn = _fn(results={h: {"requests_used": 60, "findings": 0, "endpoints": 1} for h in ("a.com", "b.com", "c.com")})
    report = ProgramRunOrchestrator.run(_scope(), fn, RunBudget(max_requests_total=100, per_asset_request_cap=300))
    statuses = {o.host: o.status for o in report.outcomes}
    assert statuses["a.com"] == "completed"
    assert statuses["b.com"] == "completed"          # clamped to remaining 40
    assert statuses["c.com"] == "budget_exhausted"
    assert report.total_requests == 100
    assert report.stopped_reason == "request_budget_exhausted"


def test_per_asset_cap_is_passed_and_spend_clamped():
    rec = []
    fn = _fn(results={"a.com": {"requests_used": 999, "endpoints": 1, "findings": 0}}, record=rec)
    report = ProgramRunOrchestrator.run(_scope(), fn, RunBudget(per_asset_request_cap=50, max_requests_total=10_000))
    assert rec[0] == ("a.com", 50)                   # cap handed to the stage
    assert report.outcomes[0].requests_used == 50    # over-report clamped to the cap


# ---------------------------------------------------------------- isolation

def test_one_asset_failure_does_not_sink_the_run():
    report = ProgramRunOrchestrator.run(_scope(), _fn(raise_on="b.com"), RunBudget(max_requests_total=10_000))
    by = {o.host: o for o in report.outcomes}
    assert by["a.com"].status == "completed"
    assert by["b.com"].status == "failed" and "boom" in by["b.com"].error
    assert by["c.com"].status == "completed"         # run continued past the failure


# --------------------------------------------------------------- stop-on-findings

def test_stops_after_findings_target():
    fn = _fn(results={"a.com": {"findings": 1, "requests_used": 5, "endpoints": 1},
                      "b.com": {"findings": 1, "requests_used": 5, "endpoints": 1}})
    report = ProgramRunOrchestrator.run(_scope(), fn, RunBudget(stop_after_findings=2, max_requests_total=10_000))
    assert report.total_findings == 2
    assert len(report.outcomes) == 2                 # c.com never hunted
    assert report.assets_skipped == 1
    assert report.stopped_reason == "findings_target_reached"


# ------------------------------------------------------------------- dry-run

def test_dry_run_plans_without_calling_the_hunt():
    def boom(asset, cap):
        raise AssertionError("hunt_asset_fn must not run in dry_run")
    report = ProgramRunOrchestrator.run(_scope(), boom, dry_run=True)
    assert [o.status for o in report.outcomes] == ["planned", "planned", "planned"]
    assert report.stopped_reason == "dry_run"


# ------------------------------------------------------------------- aggregation

def test_totals_aggregate():
    fn = _fn(results={
        "a.com": {"endpoints": 10, "findings": 2, "requests_used": 100},
        "b.com": {"endpoints": 5, "findings": 1, "requests_used": 50},
        "c.com": {"endpoints": 1, "findings": 0, "requests_used": 5},
    })
    report = ProgramRunOrchestrator.run(_scope(), fn, RunBudget(max_requests_total=10_000))
    assert report.total_findings == 3
    assert report.total_requests == 155
    assert report.assets_run == 3


def test_empty_program_is_safe():
    report = ProgramRunOrchestrator.run(ProgramScope.from_scope_tags(None), _fn())
    assert report.outcomes == [] and report.assets_run == 0
