"""Durable program-run resume: checkpoint stores + orchestrator skip/continue."""
from backend_api.services.program_scope import ProgramScope
from backend_api.services.program_run_orchestrator import ProgramRunOrchestrator, RunBudget
from backend_api.services.program_run_checkpoint import JsonCheckpointStore, MemoryCheckpointStore

TAGS = {
    "handle": "acme", "offers_bounties": True,
    "in_scope": [
        {"asset_identifier": "a.com", "asset_type": "DOMAIN", "eligible_for_bounty": True, "max_severity": "critical"},
        {"asset_identifier": "b.com", "asset_type": "DOMAIN", "eligible_for_bounty": True, "max_severity": "high"},
        {"asset_identifier": "c.com", "asset_type": "DOMAIN", "eligible_for_bounty": False, "max_severity": "low"},
    ],
}


def _scope():
    return ProgramScope.from_scope_tags(TAGS)


def _fn(called, requests_used=10, findings=0):
    def fn(asset, cap):
        called.append(asset.host)
        return {"endpoints": 2, "findings": findings, "requests_used": min(cap, requests_used)}
    return fn


# ------------------------------------------------------------- checkpoint stores

def test_memory_store_roundtrip():
    s = MemoryCheckpointStore()
    s.record("k", "a.com", {"host": "a.com", "findings": 1})
    assert s.load("k")["a.com"]["findings"] == 1
    s.finalize("k", {"total_findings": 1})
    assert s.reports["k"]["total_findings"] == 1
    s.reset("k")
    assert s.load("k") == {}


def test_json_store_persists_across_restart(tmp_path):
    JsonCheckpointStore(str(tmp_path)).record("acme", "a.com", {"host": "a.com", "findings": 2, "requests_used": 10, "status": "completed"})
    # A fresh instance (simulating a process restart) still sees it.
    reloaded = JsonCheckpointStore(str(tmp_path)).load("acme")
    assert reloaded["a.com"]["findings"] == 2
    JsonCheckpointStore(str(tmp_path)).reset("acme")
    assert JsonCheckpointStore(str(tmp_path)).load("acme") == {}


def test_json_store_sanitizes_keys(tmp_path):
    s = JsonCheckpointStore(str(tmp_path))
    s.record("weird/../key", "h", {"host": "h"})           # must not escape the dir
    assert JsonCheckpointStore(str(tmp_path)).load("weird/../key")["h"]["host"] == "h"


# --------------------------------------------------------------- resume behavior

def test_run_records_all_outcomes_to_checkpoint():
    store = MemoryCheckpointStore()
    ProgramRunOrchestrator.run(_scope(), _fn([]), RunBudget(max_requests_total=10_000),
                               checkpoint=store, run_key="acme")
    assert set(store.load("acme").keys()) == {
        "https://a.com/", "https://b.com/", "https://c.com/"
    }
    assert "total_findings" in store.reports["acme"]        # finalized


def test_resume_skips_completed_and_replays_totals():
    store = MemoryCheckpointStore()
    ProgramRunOrchestrator.run(_scope(), _fn([], findings=1), RunBudget(max_requests_total=10_000),
                               checkpoint=store, run_key="acme")
    # Resume: nothing new to hunt; totals come back from the checkpoint.
    called = []
    report = ProgramRunOrchestrator.run(_scope(), _fn(called), RunBudget(max_requests_total=10_000),
                                        checkpoint=store, resume=True, run_key="acme")
    assert called == []                                    # every asset already done -> skipped
    assert report.assets_run == 3
    assert report.total_findings == 3                      # replayed from checkpoint


def test_resume_after_crash_continues_remaining_assets():
    store = MemoryCheckpointStore()
    # Simulate a crash after only a.com finished.
    store.record("acme", "a.com", {"host": "a.com", "status": "completed", "endpoints": 5,
                                   "findings": 1, "requests_used": 50, "eligible_for_bounty": True,
                                   "max_severity": "critical"})
    called = []
    report = ProgramRunOrchestrator.run(_scope(), _fn(called), RunBudget(max_requests_total=10_000),
                                        checkpoint=store, resume=True, run_key="acme")
    assert "a.com" not in called                           # not re-hunted
    assert set(called) == {"b.com", "c.com"}               # remaining assets continued
    assert report.total_findings == 1                      # from the replayed a.com


def test_resume_budget_spans_sessions():
    store = MemoryCheckpointStore()
    store.record("k", "a.com", {"host": "a.com", "status": "completed", "endpoints": 1,
                                "findings": 0, "requests_used": 50})
    # Total budget 60, already spent 50 -> only 10 left: b.com fits, c.com is budget-exhausted.
    report = ProgramRunOrchestrator.run(_scope(), _fn([], requests_used=20),
                                        RunBudget(max_requests_total=60, per_asset_request_cap=300),
                                        checkpoint=store, resume=True, run_key="k")
    by = {o.host: o for o in report.outcomes}
    assert by["b.com"].status == "completed" and by["b.com"].requests_used == 10
    assert by["c.com"].status == "budget_exhausted"
    assert report.stopped_reason == "request_budget_exhausted"
