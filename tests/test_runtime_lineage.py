"""Runtime lineage stays bounded, source-free, and epistemically conservative."""
from __future__ import annotations

import json
from pathlib import Path

from analysis_engine.runtime_lineage import RuntimeLineageAnalyzer, analyze


def _source(
    *,
    event_id: str = "source-1",
    context_id: str = "ctx-1",
    ts_ms: int = 1_000,
    fingerprint: str = "a" * 64,
    **extra,
) -> dict:
    return {
        "kind": "source",
        "event_id": event_id,
        "context_id": context_id,
        "source": "location.hash",
        "stack_fingerprint": fingerprint,
        "ts_ms": ts_ms,
        **extra,
    }


def _sink(
    *,
    event_id: str = "sink-1",
    context_id: str = "ctx-1",
    ts_ms: int = 1_010,
    fingerprint: str = "b" * 64,
    **extra,
) -> dict:
    return {
        "kind": "sink",
        "event_id": event_id,
        "context_id": context_id,
        "sink": "innerHTML",
        "stack_fingerprint": fingerprint,
        "ts_ms": ts_ms,
        **extra,
    }


def _aab(candidate: dict) -> list[dict]:
    common = {
        "candidate_id": candidate["candidate_id"],
        "sink_fingerprint": candidate["sink_fingerprint"],
        "inert": True,
    }
    return [
        {
            **common,
            "run_id": "run-a-1",
            "arm": "A",
            "stimulus_fingerprint": "c" * 64,
            "observation_fingerprint": "d" * 64,
        },
        {
            **common,
            "run_id": "run-a-2",
            "arm": "A",
            "stimulus_fingerprint": "c" * 64,
            "observation_fingerprint": "d" * 64,
        },
        {
            **common,
            "run_id": "run-b-1",
            "arm": "B",
            "stimulus_fingerprint": "e" * 64,
            "observation_fingerprint": "f" * 64,
        },
    ]


def test_direct_runtime_order_is_only_causal_evidence_and_source_free():
    secret = "RAW_SECRET_VALUE_8c27"
    events = [
        _source(
            value=secret,
            source_text=f"const token = '{secret}'",
            filename=f"https://target.test/app.js?token={secret}",
        ),
        _sink(value=secret, oracle_hit=True, executed=True),
    ]

    result = analyze(events)

    assert result["summary"]["causal_only"] == 1
    assert result["summary"]["value_influence"] == 0
    assert result["value_influences"] == []
    flow = result["causal_flows"][0]
    assert flow["classification"] == "causal_only"
    assert flow["source_category"] == "location_hash"
    assert flow["sink_category"] == "innerhtml"
    assert flow["relation"] == "direct"
    assert flow["depth"] == 1
    assert flow["latency_ms"] == 10
    serialized = json.dumps(result, sort_keys=True)
    assert secret not in serialized
    assert "filename" not in serialized
    assert "source_text" not in serialized
    assert "oracle_hit" not in serialized
    assert "executed" not in serialized


def test_parent_context_chain_preserves_async_causality():
    events = [
        _source(context_id="root", ts_ms=100),
        _sink(
            context_id="promise-1",
            parent_context_id="root",
            relation="async",
            ts_ms=125,
        ),
    ]

    flow = analyze(events)["causal_flows"][0]

    assert flow["source_context_id"] == "root"
    assert flow["sink_context_id"] == "promise-1"
    assert flow["relation"] == "async"
    assert flow["depth"] == 2
    assert flow["latency_ms"] == 25


def test_equal_explicit_source_and_sink_contexts_are_a_direct_flow():
    result = analyze([
        _source(source_context_id="shared-context"),
        _sink(
            context_id="unused-context-alias",
            source_context_id="shared-context",
            sink_context_id="shared-context",
        ),
    ])

    assert result["summary"]["causal_only"] == 1
    assert result["causal_flows"][0]["relation"] == "direct"


def test_conflicting_parent_contexts_never_leave_an_earlier_async_candidate():
    result = analyze([
        _source(context_id="parent-a", ts_ms=1),
        _sink(
            event_id="first-sink",
            context_id="child",
            parent_context_id="parent-a",
            relation="async",
            ts_ms=2,
        ),
        _sink(
            event_id="second-sink",
            context_id="child",
            parent_context_id="parent-b",
            relation="async",
            ts_ms=3,
        ),
    ])

    assert result["summary"]["candidates"] == 0


def test_candidate_identity_is_stable_across_ephemeral_event_and_context_ids():
    first = analyze([
        _source(event_id="src-run-1", context_id="ctx-run-1"),
        _sink(event_id="sink-run-1", context_id="ctx-run-1"),
    ])["causal_flows"][0]
    second = analyze([
        _source(event_id="src-run-2", context_id="ctx-run-2"),
        _sink(event_id="sink-run-2", context_id="ctx-run-2"),
    ])["causal_flows"][0]

    assert first["candidate_id"] == second["candidate_id"]
    assert first["source_id"] != second["source_id"]
    assert first["sink_id"] != second["sink_id"]


def test_ttl_and_depth_bounds_block_distant_correlations():
    expired = analyze([
        _source(ts_ms=0),
        _sink(ts_ms=5_001),
    ])
    assert expired["causal_flows"] == []

    within_depth = [_source(context_id="ctx-0", ts_ms=0)]
    for index in range(1, 8):
        within_depth.append(_sink(
            event_id=f"sink-{index}",
            context_id=f"ctx-{index}",
            parent_context_id=f"ctx-{index - 1}",
            relation="async",
            ts_ms=index,
            fingerprint=f"{index}" * 64,
        ))
    bounded = analyze(within_depth)
    deepest = next(
        item for item in bounded["causal_flows"] if item["sink_id"] == "sink-7"
    )
    assert deepest["depth"] == 8

    beyond_depth = within_depth + [_sink(
        event_id="sink-8",
        context_id="ctx-8",
        parent_context_id="ctx-7",
        relation="async",
        ts_ms=8,
        fingerprint="8" * 64,
    )]
    too_deep = analyze(beyond_depth)
    assert not any(
        item["source_id"] == "source-1" and item["sink_id"] == "sink-8"
        for item in too_deep["causal_flows"] + too_deep["value_influences"]
    )

    invalid_declared_depth = analyze([
        _source(depth=0),
        _sink(depth=9),
    ])
    assert invalid_declared_depth["summary"]["events_accepted"] == 1
    assert invalid_declared_depth["summary"]["candidates"] == 0


def test_only_allowlisted_normalized_metadata_is_accepted():
    events = [
        _source(),
        _sink(),
        _source(event_id="unknown-source", source="location.ancestorOrigins"),
        _sink(event_id="unknown-sink", sink="textContent"),
        _sink(event_id="bad-fingerprint", fingerprint="not-a-sha256"),
        _sink(event_id="bad-relation", relation="maybe"),
        {**_sink(event_id="bad-kind"), "kind": "execute"},
        {**_sink(event_id="bad-time"), "ts_ms": float("nan")},
    ]

    result = analyze(events)

    assert result["summary"]["events_seen"] == 8
    assert result["summary"]["events_accepted"] == 2
    assert result["summary"]["events_rejected"] == 6
    assert result["summary"]["candidates"] == 1


def test_stable_inert_aab_upgrades_the_same_sink_to_value_influence():
    events = [_source(), _sink()]
    candidate = analyze(events)["causal_flows"][0]

    result = RuntimeLineageAnalyzer.analyze(events, _aab(candidate))

    assert result["causal_flows"] == []
    assert result["summary"]["value_influence"] == 1
    influence = result["value_influences"][0]
    assert influence["classification"] == "value_influence"
    assert influence["candidate_id"] == candidate["candidate_id"]
    assert influence["sink_fingerprint"] == candidate["sink_fingerprint"]
    assert influence["aab"] == {
        "pattern": "A/A/B",
        "runs": 3,
        "stable_a": True,
        "b_changed": True,
        "inert": True,
    }
    serialized = json.dumps(result, sort_keys=True)
    assert "c" * 64 not in serialized
    assert "d" * 64 not in serialized
    assert "run-a-1" not in serialized


def test_unstable_a_or_unchanged_b_remains_causal_only():
    events = [_source(), _sink()]
    candidate = analyze(events)["causal_flows"][0]
    unstable = _aab(candidate)
    unstable[1]["observation_fingerprint"] = "1" * 64
    unchanged = _aab(candidate)
    unchanged[2]["observation_fingerprint"] = "d" * 64

    for observations in (unstable, unchanged):
        result = analyze(events, observations)
        assert result["summary"]["causal_only"] == 1
        assert result["value_influences"] == []


def test_aab_requires_inert_order_unique_runs_and_exact_sink_identity():
    events = [_source(), _sink()]
    candidate = analyze(events)["causal_flows"][0]
    active = _aab(candidate)
    active[2]["inert"] = False
    wrong_order = [_aab(candidate)[2], *_aab(candidate)[:2]]
    duplicate_run = _aab(candidate)
    duplicate_run[1]["run_id"] = duplicate_run[0]["run_id"]
    wrong_sink = _aab(candidate)
    wrong_sink[2]["sink_fingerprint"] = "1" * 64
    contradictory_ids = _aab(candidate)
    contradictory_ids[2]["source_id"] = "different-source"

    for observations in (
        active,
        wrong_order,
        duplicate_run,
        wrong_sink,
        contradictory_ids,
    ):
        result = analyze(events, observations)
        assert result["summary"]["value_influence"] == 0
        assert result["causal_flows"][0]["classification"] == "causal_only"


def test_observations_can_match_one_unambiguous_source_sink_pair_without_id():
    events = [_source(), _sink()]
    candidate = analyze(events)["causal_flows"][0]
    observations = _aab(candidate)
    for observation in observations:
        observation.pop("candidate_id")
        observation["source_id"] = candidate["source_id"]
        observation["sink_id"] = candidate["sink_id"]

    result = analyze(events, observations)

    assert result["summary"]["value_influence"] == 1


def test_event_candidate_and_observation_budgets_are_explicit():
    events = [_source(ts_ms=0)]
    events.extend(
        _sink(
            event_id=f"sink-{index}",
            ts_ms=index,
            fingerprint=f"{index % 10}" * 64,
        )
        for index in range(1, 258)
    )
    observations = [
        {
            "run_id": f"run-{index}",
            "arm": "A" if index < 2 else "B",
            "candidate_id": "1" * 64,
            "sink_fingerprint": "2" * 64,
            "stimulus_fingerprint": "3" * 64,
            "observation_fingerprint": "4" * 64,
            "inert": True,
        }
        for index in range(25)
    ]

    result = analyze(events, observations)

    assert set(result["budget_exhausted"]) == {
        "events", "candidates", "observations"
    }
    assert result["limits"]["max_depth"] == 8
    assert result["limits"]["ttl_ms"] == 5_000
    assert result["limits"]["max_events"] == 256
    assert result["limits"]["max_candidates"] == 8
    assert result["limits"]["max_observations"] == 24
    assert result["limits"]["max_runs"] == 24
    assert result["summary"]["events_seen"] == 256
    assert result["summary"]["observations_seen"] == 24
    assert result["summary"]["candidates"] == 8


def test_run_budget_rejects_excess_unique_runs(monkeypatch):
    candidate = analyze([_source(), _sink()])["causal_flows"][0]
    observations = _aab(candidate)
    monkeypatch.setattr(RuntimeLineageAnalyzer, "MAX_RUNS", 2)

    result = RuntimeLineageAnalyzer.analyze([_source(), _sink()], observations)

    assert result["limits"]["runs_truncated"] is True
    assert "runs" in result["budget_exhausted"]
    assert result["summary"]["observations_accepted"] == 2
    assert result["summary"]["observations_rejected"] == 1
    assert result["value_influences"] == []


def test_reduced_class_limits_are_enforced_and_reported(monkeypatch):
    monkeypatch.setattr(RuntimeLineageAnalyzer, "MAX_DEPTH", 1)
    monkeypatch.setattr(RuntimeLineageAnalyzer, "TTL_MS", 1)
    result = RuntimeLineageAnalyzer.analyze([
        _source(context_id="parent", ts_ms=1),
        _sink(
            context_id="child",
            parent_context_id="parent",
            relation="async",
            ts_ms=2,
        ),
        _sink(event_id="late", context_id="parent", ts_ms=3),
    ])

    assert result["limits"]["max_depth"] == 1
    assert result["limits"]["ttl_ms"] == 1
    assert result["summary"]["candidates"] == 0


def test_out_of_order_records_do_not_create_reverse_time_lineage():
    result = analyze([
        _sink(ts_ms=100),
        _source(ts_ms=101),
    ])

    assert result["summary"]["candidates"] == 0
    assert result["causal_flows"] == []
    assert result["value_influences"] == []


def test_oracle_source_hooks_observe_without_mutating_returned_data():
    oracle = (
        Path(__file__).resolve().parents[1] / "browser_workers" / "oracle_inject.js"
    ).read_text(encoding="utf-8")

    assert "val = val + marker" not in oracle
    assert "__taint_" not in oracle
    assert "__XSS_CAUSAL_LINEAGE__" in oracle
    assert "recordCausalSource(sourceName, stack, 'getter_read');" in oracle
    assert "return val;" in oracle
