"""Inert A/A/B probe coordination is passive, bounded, and thread-safe."""
from __future__ import annotations

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor

import pytest

from analysis_engine.runtime_lineage import analyze
from analysis_engine.runtime_lineage_probe import (
    MAX_REPORT_OBSERVATIONS,
    MAX_STATES,
    STATE_TTL_SECONDS,
    RuntimeLineageProbeCoordinator,
)


def _fp(character: str) -> str:
    return character * 64


def _observation(
    step: dict,
    result_fingerprint: str,
    **overrides,
) -> dict:
    probe = step["runtime_lineage_probe"]
    return {
        "run_id": probe["run_id"],
        "arm": probe["arm"],
        "inert": True,
        "candidate_id": step["candidate_id"],
        "sink_fingerprint": step["sink_fingerprint"],
        "stimulus_fingerprint": probe["stimulus_fingerprint"],
        "observation_fingerprint": result_fingerprint,
        **overrides,
    }


def _report(*observations: dict, **extra) -> dict:
    return {
        "probe_observations": list(observations),
        **extra,
    }


def _complete(
    coordinator: RuntimeLineageProbeCoordinator,
    *,
    results: tuple[str, str, str] = (_fp("c"), _fp("c"), _fp("d")),
    key: str = "series-1",
    candidate: str = _fp("a"),
    sink: str = _fp("b"),
    marker: str = "SafeMarker123",
) -> tuple[list[dict], dict]:
    steps: list[dict] = []
    step = coordinator.begin(key, candidate, sink, marker)
    for result in results:
        steps.append(step)
        step = coordinator.accept_report(
            key,
            candidate,
            _report(_observation(step, result)),
        )
    return steps, step


def test_begin_returns_only_an_alphanumeric_marker_preserving_a_probe():
    coordinator = RuntimeLineageProbeCoordinator()

    step = coordinator.begin(
        "series-1", _fp("a"), _fp("b"), "ExistingMarker42"
    )

    probe = step["runtime_lineage_probe"]
    assert step["status"] == "probe"
    assert step["next_arm"] == "A"
    assert probe["arm"] == "A"
    assert probe["inert"] is True
    assert probe["stimulus"].startswith("ExistingMarker42")
    assert re.fullmatch(r"[A-Za-z0-9]+", probe["stimulus"])
    assert probe["stimulus_fingerprint"] == hashlib.sha256(
        probe["stimulus"].encode("ascii")
    ).hexdigest()
    assert step["runtime_lineage_observations"] == []
    assert "execution" not in json.dumps(step).lower()


def test_exact_a_a_b_sequence_uses_stable_a_and_unique_run_ids():
    coordinator = RuntimeLineageProbeCoordinator()

    steps, complete = _complete(coordinator)

    assert [step["next_arm"] for step in steps] == ["A", "A", "B"]
    probes = [step["runtime_lineage_probe"] for step in steps]
    assert probes[0]["stimulus"] == probes[1]["stimulus"]
    assert probes[2]["stimulus"] != probes[0]["stimulus"]
    assert all(
        probe["stimulus"].startswith("SafeMarker123")
        and probe["stimulus"].isalnum()
        for probe in probes
    )
    assert len({probe["run_id"] for probe in probes}) == 3
    assert complete["status"] == "complete"
    assert complete["classification"] == "value_influence"
    assert complete["aab"] == {
        "pattern": "A/A/B",
        "runs": 3,
        "stable_a": True,
        "b_changed": True,
        "inert": True,
    }
    assert len(complete["runtime_lineage_observations"]) == 3
    assert "stimulus" not in complete


def test_unstable_a_or_unchanged_b_completes_as_causal_only():
    unstable = RuntimeLineageProbeCoordinator()
    _, unstable_result = _complete(
        unstable,
        results=(_fp("c"), _fp("d"), _fp("e")),
    )
    unchanged = RuntimeLineageProbeCoordinator()
    _, unchanged_result = _complete(
        unchanged,
        results=(_fp("c"), _fp("c"), _fp("c")),
    )

    assert unstable_result["classification"] == "causal_only"
    assert unstable_result["aab"]["stable_a"] is False
    assert unchanged_result["classification"] == "causal_only"
    assert unchanged_result["aab"]["b_changed"] is False


def test_report_summary_and_classification_never_advance_state():
    coordinator = RuntimeLineageProbeCoordinator()
    first = coordinator.begin("series-1", _fp("a"), _fp("b"), "Marker")

    result = coordinator.accept_report(
        "series-1",
        _fp("a"),
        {
            "summary": {"value_influence": 999},
            "classification": "value_influence",
            "value_influences": [{"execution_confirmed": True}],
        },
    )

    assert result["status"] == "awaiting_observation"
    assert result["runtime_lineage_probe"] == first["runtime_lineage_probe"]
    assert result["runtime_lineage_observations"] == []


@pytest.mark.parametrize(
    "overrides",
    [
        {"inert": False},
        {"run_id": "wrong-run"},
        {"arm": "B"},
        {"candidate_id": _fp("c")},
        {"sink_fingerprint": _fp("c")},
        {"stimulus_fingerprint": _fp("c")},
        {"observation_fingerprint": "not-a-fingerprint"},
    ],
)
def test_only_the_exact_expected_source_free_observation_advances(overrides):
    coordinator = RuntimeLineageProbeCoordinator()
    first = coordinator.begin("series-1", _fp("a"), _fp("b"), "Marker")
    hostile = _observation(first, _fp("c"), raw_value="secret", **overrides)

    result = coordinator.accept_report(
        "series-1",
        _fp("a"),
        _report(hostile, summary={"value_influence": 1}),
    )

    assert result["status"] == "awaiting_observation"
    assert result["runtime_lineage_probe"] == first["runtime_lineage_probe"]
    assert result["runtime_lineage_observations"] == []
    assert "secret" not in json.dumps(result)


def test_other_candidates_in_the_same_executor_run_are_ignored():
    coordinator = RuntimeLineageProbeCoordinator()
    first = coordinator.begin("series-1", _fp("a"), _fp("b"), "Marker")
    other = _observation(first, _fp("c"), candidate_id=_fp("d"))
    expected = _observation(first, _fp("c"))

    result = coordinator.accept_report(
        "series-1",
        _fp("a"),
        _report(other, expected),
    )

    assert result["status"] == "probe"
    assert result["next_arm"] == "A"
    assert len(result["runtime_lineage_observations"]) == 1


def test_cumulative_executor_snapshots_advance_only_the_outstanding_run():
    coordinator = RuntimeLineageProbeCoordinator()
    first = coordinator.begin("series-1", _fp("a"), _fp("b"), "Marker")
    first_observation = _observation(first, _fp("c"))
    second = coordinator.accept_report(
        "series-1", _fp("a"), _report(first_observation)
    )
    second_observation = _observation(second, _fp("c"))
    third = coordinator.accept_report(
        "series-1",
        _fp("a"),
        _report(first_observation, second_observation),
    )
    third_observation = _observation(third, _fp("d"))

    complete = coordinator.accept_report(
        "series-1",
        _fp("a"),
        _report(first_observation, second_observation, third_observation),
    )

    assert complete["status"] == "complete"
    assert complete["classification"] == "value_influence"
    assert len(complete["runtime_lineage_observations"]) == 3


def test_same_candidate_in_different_series_never_shares_run_state():
    coordinator = RuntimeLineageProbeCoordinator()
    first = coordinator.begin("series-one", _fp("a"), _fp("b"), "Marker")
    second = coordinator.begin("series-two", _fp("a"), _fp("b"), "Marker")

    wrong_series = coordinator.accept_report(
        "series-two",
        _fp("a"),
        _report(_observation(first, _fp("c"))),
    )

    assert first["series_id"] != second["series_id"]
    assert first["runtime_lineage_probe"]["run_id"] != (
        second["runtime_lineage_probe"]["run_id"]
    )
    assert wrong_series["status"] == "awaiting_observation"
    assert wrong_series["runtime_lineage_observations"] == []


def test_report_observation_scan_is_bounded_to_twenty_four():
    coordinator = RuntimeLineageProbeCoordinator()
    first = coordinator.begin("series-1", _fp("a"), _fp("b"), "Marker")
    unrelated = [
        _observation(first, _fp("c"), candidate_id=_fp("d"))
        for _ in range(MAX_REPORT_OBSERVATIONS)
    ]
    expected = _observation(first, _fp("c"))

    result = coordinator.accept_report(
        "series-1",
        _fp("a"),
        _report(*unrelated, expected),
    )

    assert result["status"] == "awaiting_observation"
    assert result["runtime_lineage_observations"] == []


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_ttl_expiry_is_lazy_exact_and_rejects_late_reports():
    clock = _Clock()
    coordinator = RuntimeLineageProbeCoordinator(ttl_seconds=10, clock=clock)
    first = coordinator.begin("series-1", _fp("a"), _fp("b"), "Marker")
    report = _report(_observation(first, _fp("c")))

    clock.now = 10.0
    expired = coordinator.accept_report("series-1", _fp("a"), report)
    replacement = coordinator.begin("series-1", _fp("a"), _fp("b"), "Marker")

    assert expired["status"] == "missing"
    assert replacement["runtime_lineage_probe"]["run_id"] != (
        first["runtime_lineage_probe"]["run_id"]
    )
    assert coordinator.size == 1


def test_accepting_an_arm_does_not_extend_the_hard_ttl():
    clock = _Clock()
    coordinator = RuntimeLineageProbeCoordinator(ttl_seconds=10, clock=clock)
    first = coordinator.begin("series-1", _fp("a"), _fp("b"), "Marker")
    clock.now = 9.0
    second = coordinator.accept_report(
        "series-1",
        _fp("a"),
        _report(_observation(first, _fp("c"))),
    )
    assert second["status"] == "probe"

    clock.now = 10.0
    assert coordinator.status("series-1", _fp("a"))["status"] == "missing"


def test_lru_evicts_the_least_recent_series_at_capacity():
    coordinator = RuntimeLineageProbeCoordinator(max_states=2)
    first = coordinator.begin("one", _fp("a"), _fp("b"), "Marker")
    coordinator.begin("two", _fp("c"), _fp("d"), "Marker")
    coordinator.status("one", _fp("a"))
    coordinator.begin("three", _fp("e"), _fp("f"), "Marker")

    assert coordinator.size == 2
    assert coordinator.status("one", _fp("a"))["series_id"] == first["series_id"]
    assert coordinator.status("two", _fp("c"))["status"] == "missing"
    assert coordinator.status("three", _fp("e"))["status"] == "probe"


def test_concurrent_begin_and_duplicate_completion_advance_once():
    coordinator = RuntimeLineageProbeCoordinator()

    with ThreadPoolExecutor(max_workers=8) as pool:
        starts = list(pool.map(
            lambda _index: coordinator.begin(
                "shared", _fp("a"), _fp("b"), "Marker"
            ),
            range(24),
        ))

    assert coordinator.size == 1
    assert len({item["runtime_lineage_probe"]["run_id"] for item in starts}) == 1
    first = starts[0]
    report = _report(_observation(first, _fp("c")))

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(
            lambda _index: coordinator.accept_report("shared", _fp("a"), report),
            range(24),
        ))

    current = coordinator.status("shared", _fp("a"))
    assert current["next_arm"] == "A"
    assert len(current["runtime_lineage_observations"]) == 1
    assert current["runtime_lineage_probe"]["run_id"] != (
        first["runtime_lineage_probe"]["run_id"]
    )


def test_conflicting_duplicate_run_observation_prevents_value_influence():
    coordinator = RuntimeLineageProbeCoordinator()
    first = coordinator.begin("shared", _fp("a"), _fp("b"), "Marker")
    second = coordinator.accept_report(
        "shared", _fp("a"), _report(_observation(first, _fp("c")))
    )
    conflict = coordinator.accept_report(
        "shared", _fp("a"), _report(_observation(first, _fp("d")))
    )
    assert conflict["status"] == "awaiting_observation"

    third = coordinator.accept_report(
        "shared", _fp("a"), _report(_observation(second, _fp("c")))
    )
    complete = coordinator.accept_report(
        "shared", _fp("a"), _report(_observation(third, _fp("d")))
    )

    assert complete["status"] == "complete"
    assert complete["classification"] == "causal_only"
    assert complete["aab"]["stable_a"] is False
    assert complete["aab"]["b_changed"] is False


def test_returned_data_is_copied_and_hostile_report_fields_never_persist():
    coordinator = RuntimeLineageProbeCoordinator()
    first = coordinator.begin("series-1", _fp("a"), _fp("b"), "Marker")
    first["runtime_lineage_probe"]["arm"] = "B"
    first["runtime_lineage_observations"].append({"raw": "mutation"})
    current = coordinator.status("series-1", _fp("a"))
    assert current["runtime_lineage_probe"]["arm"] == "A"
    assert current["runtime_lineage_observations"] == []

    accepted = coordinator.accept_report(
        "series-1",
        _fp("a"),
        _report(
            _observation(current, _fp("c"), value="RAW_SECRET", url="private"),
            raw_source="PRIVATE_SOURCE",
        ),
    )
    accepted["runtime_lineage_observations"][0]["observation_fingerprint"] = _fp("f")
    persisted = coordinator.status("series-1", _fp("a"))
    serialized = json.dumps(persisted, sort_keys=True)

    assert persisted["runtime_lineage_observations"][0][
        "observation_fingerprint"
    ] == _fp("c")
    assert "RAW_SECRET" not in serialized
    assert "PRIVATE_SOURCE" not in serialized
    assert "private" not in serialized


def test_constructor_and_marker_validation_keep_hard_bounds():
    bounded = RuntimeLineageProbeCoordinator(
        max_states=MAX_STATES * 10,
        ttl_seconds=STATE_TTL_SECONDS * 10,
    )
    assert bounded.max_states == MAX_STATES
    assert bounded.ttl_seconds == STATE_TTL_SECONDS

    with pytest.raises(ValueError):
        RuntimeLineageProbeCoordinator(max_states=0)
    with pytest.raises(ValueError):
        RuntimeLineageProbeCoordinator(ttl_seconds=float("inf"))
    with pytest.raises(ValueError):
        bounded.begin("series", _fp("a"), _fp("b"), "unsafe-marker")
    with pytest.raises(ValueError):
        bounded.begin("series", "bad", _fp("b"), "Marker")


def test_reduced_report_scan_limit_is_enforced_and_reported(monkeypatch):
    monkeypatch.setattr(RuntimeLineageProbeCoordinator, "MAX_REPORT_OBSERVATIONS", 1)
    coordinator = RuntimeLineageProbeCoordinator()
    first = coordinator.begin("series", _fp("a"), _fp("b"), "Marker")
    unrelated = _observation(first, _fp("c"), candidate_id=_fp("d"))
    expected = _observation(first, _fp("c"))

    result = coordinator.accept_report(
        "series", _fp("a"), _report(unrelated, expected)
    )

    assert result["limits"]["max_report_observations"] == 1
    assert result["status"] == "awaiting_observation"


def test_completed_observations_feed_the_runtime_lineage_analyzer_directly():
    events = [
        {
            "kind": "source",
            "event_id": "src-1",
            "context_id": "ctx-1",
            "source_category": "location_hash",
            "source_fingerprint": _fp("a"),
            "ts_ms": 1,
        },
        {
            "kind": "sink",
            "event_id": "sink-1",
            "context_id": "ctx-1",
            "sink_category": "innerhtml",
            "sink_fingerprint": _fp("b"),
            "ts_ms": 2,
        },
    ]
    causal = analyze(events)["causal_flows"][0]
    coordinator = RuntimeLineageProbeCoordinator()
    _, complete = _complete(
        coordinator,
        candidate=causal["candidate_id"],
        sink=causal["sink_fingerprint"],
    )

    result = analyze(events, complete["runtime_lineage_observations"])

    assert result["summary"]["value_influence"] == 1
    assert result["value_influences"][0]["candidate_id"] == causal["candidate_id"]
