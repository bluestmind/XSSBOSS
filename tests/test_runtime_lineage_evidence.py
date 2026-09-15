"""API-boundary tests for self-consistent, value-free lineage evidence."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from backend_api.schemas.experiment import MonitorExecutionResponse
from backend_api.utils.runtime_lineage_evidence import (
    classify_runtime_lineage,
    normalize_runtime_lineage_evidence,
    seal_runtime_lineage_probe_evidence,
)


def _candidate_id(
    source_category: str,
    source_fingerprint: str,
    sink_category: str,
    sink_fingerprint: str,
) -> str:
    canonical = json.dumps({
        "source_category": source_category,
        "source_fingerprint": source_fingerprint,
        "sink_category": sink_category,
        "sink_fingerprint": sink_fingerprint,
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _lineage_fixture() -> dict:
    causal_candidate = _candidate_id("url_param", "a" * 64, "innerhtml", "b" * 64)
    value_candidate = _candidate_id("location_hash", "c" * 64, "navigation", "d" * 64)
    return {
        "schema_version": "1.0",
        "interpretation": "untrusted free-form text must be replaced",
        "limits": {
            "max_depth": 8,
            "ttl_ms": 5000,
            "max_events": 256,
            "max_candidates": 8,
            "max_observations": 24,
            "max_runs": 24,
            "events_truncated": False,
            "candidates_truncated": False,
            "observations_truncated": False,
            "runs_truncated": False,
            "secret": "must-not-survive",
        },
        "budget_exhausted": [],
        "summary": {
            "events_seen": 12,
            "events_accepted": 10,
            "events_rejected": 2,
            "observations_seen": 3,
            "observations_accepted": 3,
            "observations_rejected": 0,
            "candidates": 2,
            "causal_only": 1,
            "value_influence": 1,
            "raw_value": "must-not-survive",
        },
        "causal_flows": [{
            "candidate_id": causal_candidate,
            "classification": "causal_only",
            "source_id": "RAW_SECRET_SOURCE_ID",
            "source_category": "url_param",
            "source_fingerprint": "a" * 64,
            "sink_id": "RAW_SECRET_SINK_ID",
            "sink_category": "innerhtml",
            "sink_fingerprint": "b" * 64,
            "relation": "async",
            "depth": 2,
            "latency_ms": 15,
            "raw_value": "must-not-survive",
            "url": "https://private.invalid/path?token=secret",
        }],
        "value_influences": [{
            "candidate_id": value_candidate,
            "classification": "value_influence",
            "source_id": "source:ephemeral",
            "source_category": "location_hash",
            "source_fingerprint": "c" * 64,
            "sink_id": "sink:ephemeral",
            "sink_category": "navigation",
            "sink_fingerprint": "d" * 64,
            "relation": "direct",
            "depth": 1,
            "latency_ms": 0,
            "source_text": "must-not-survive",
            "aab": {
                "pattern": "A/A/B",
                "runs": 3,
                "stable_a": True,
                "b_changed": True,
                "inert": True,
            },
        }],
        "probe_observations": [
            {
                "run_id": "rlp:7777777777777777:0123456789abcdef:1",
                "arm": "A",
                "inert": True,
                "candidate_id": value_candidate,
                "sink_fingerprint": "d" * 64,
                "stimulus_fingerprint": "e" * 64,
                "observation_fingerprint": "1" * 64,
            },
            {
                "run_id": "rlp:7777777777777777:0123456789abcdef:2",
                "arm": "A",
                "inert": True,
                "candidate_id": value_candidate,
                "sink_fingerprint": "d" * 64,
                "stimulus_fingerprint": "e" * 64,
                "observation_fingerprint": "1" * 64,
            },
            {
                "run_id": "rlp:7777777777777777:0123456789abcdef:3",
                "arm": "B",
                "inert": True,
                "candidate_id": value_candidate,
                "sink_fingerprint": "d" * 64,
                "stimulus_fingerprint": "f" * 64,
                "observation_fingerprint": "2" * 64,
            },
        ],
        "source_text": "must-not-survive",
    }


def _sealed_lineage(*, test_case_id: int = 2, attempt_no: int = 1) -> dict:
    raw = _lineage_fixture()
    sealed = seal_runtime_lineage_probe_evidence(
        raw,
        test_case_id=test_case_id,
        attempt_no=attempt_no,
        series_id="7" * 64,
        accepted_observations=raw["probe_observations"],
    )
    assert sealed is not None
    return sealed


def test_normalizer_keeps_only_verified_bounded_metadata() -> None:
    normalized = normalize_runtime_lineage_evidence(
        _sealed_lineage(), test_case_id=2, attempt_no=1
    )

    assert normalized is not None
    assert normalized["schema_version"] == "runtime-causal-lineage/v1"
    assert normalized["summary"]["candidates"] == 2
    assert normalized["budget_exhausted"] == []
    assert normalized["limits"]["events_truncated"] is False
    assert normalized["causal_flows"][0]["source_fingerprint"] != "a" * 64
    assert normalized["value_influences"][0]["source_fingerprint"] != "c" * 64
    assert len(normalized["aab_observations"]) == 3
    assert "run_id_fingerprint" in normalized["aab_observations"][0]
    assert normalize_runtime_lineage_evidence(
        normalized, test_case_id=2, attempt_no=1
    ) == normalized
    serialized = repr(normalized)
    for secret in (
        "must-not-survive",
        "private.invalid",
        "RAW_SECRET_SOURCE_ID",
        "RAW_SECRET_SINK_ID",
        "rlp:7777777777777777:0123456789abcdef:1",
    ):
        assert secret not in serialized
    assert "source_id" not in normalized["causal_flows"][0]
    assert "sink_id" not in normalized["causal_flows"][0]


def test_value_influence_is_the_strongest_classification() -> None:
    assert classify_runtime_lineage(
        _sealed_lineage(), test_case_id=2, attempt_no=1
    ) == "value_influence"
    causal = _lineage_fixture()
    causal["summary"]["candidates"] = 1
    causal["summary"]["value_influence"] = 0
    causal["value_influences"] = []
    assert classify_runtime_lineage(
        causal, test_case_id=9, attempt_no=1
    ) == "causal_only"
    assert classify_runtime_lineage({"summary": {}}) is None


def test_causal_projection_is_bound_to_test_case_and_attempt() -> None:
    causal = _lineage_fixture()
    causal["summary"]["candidates"] = 1
    causal["summary"]["value_influence"] = 0
    causal["value_influences"] = []
    causal.pop("probe_observations")

    bound = normalize_runtime_lineage_evidence(
        causal, test_case_id=23, attempt_no=4
    )

    assert bound is not None
    assert normalize_runtime_lineage_evidence(
        bound, test_case_id=23, attempt_no=4
    ) == bound
    assert normalize_runtime_lineage_evidence(
        bound, test_case_id=24, attempt_no=4
    ) is None
    assert normalize_runtime_lineage_evidence(
        bound, test_case_id=23, attempt_no=5
    ) is None
    assert normalize_runtime_lineage_evidence(bound) is None


def test_summary_only_or_unproven_value_influence_is_not_trusted() -> None:
    assert classify_runtime_lineage({
        "schema_version": "runtime-causal-lineage/v1",
        "summary": {"value_influence": 99},
    }) is None
    assert normalize_runtime_lineage_evidence(_lineage_fixture()) is None

    for mutation in ("missing-metadata", "missing-proof", "conflicting-proof"):
        unproven = _lineage_fixture()
        if mutation == "missing-metadata":
            unproven["value_influences"][0].pop("aab")
        elif mutation == "missing-proof":
            unproven.pop("probe_observations")
        else:
            unproven["probe_observations"][1]["observation_fingerprint"] = "3" * 64
        assert seal_runtime_lineage_probe_evidence(
            unproven,
            test_case_id=2,
            attempt_no=1,
            series_id="7" * 64,
            accepted_observations=unproven.get("probe_observations"),
        ) is None


def test_replayed_or_structurally_forged_proof_is_rejected() -> None:
    replayed = _lineage_fixture()
    replayed["probe_observations"][1]["run_id"] = (
        "rlp:7777777777777777:0123456789abcdef:1"
    )
    assert seal_runtime_lineage_probe_evidence(
        replayed,
        test_case_id=2,
        attempt_no=1,
        series_id="7" * 64,
        accepted_observations=replayed["probe_observations"],
    ) is None

    arbitrary_candidate = _lineage_fixture()
    arbitrary_candidate["value_influences"][0]["candidate_id"] = "9" * 64
    for item in arbitrary_candidate["probe_observations"]:
        item["candidate_id"] = "9" * 64
    assert seal_runtime_lineage_probe_evidence(
        arbitrary_candidate,
        test_case_id=2,
        attempt_no=1,
        series_id="7" * 64,
        accepted_observations=arbitrary_candidate["probe_observations"],
    ) is None

    mismatched_sink = _lineage_fixture()
    mismatched_sink["probe_observations"][2]["sink_fingerprint"] = "8" * 64
    assert seal_runtime_lineage_probe_evidence(
        mismatched_sink,
        test_case_id=2,
        attempt_no=1,
        series_id="7" * 64,
        accepted_observations=mismatched_sink["probe_observations"],
    ) is None

    wrong_series = _lineage_fixture()
    wrong_series["probe_observations"][2]["run_id"] = (
        "rlp:8888888888888888:0123456789abcdef:3"
    )
    assert seal_runtime_lineage_probe_evidence(
        wrong_series,
        test_case_id=2,
        attempt_no=1,
        series_id="7" * 64,
        accepted_observations=wrong_series["probe_observations"],
    ) is None

    mixed_nonce = _lineage_fixture()
    mixed_nonce["probe_observations"][2]["run_id"] = (
        "rlp:7777777777777777:fedcba9876543210:3"
    )
    assert seal_runtime_lineage_probe_evidence(
        mixed_nonce,
        test_case_id=2,
        attempt_no=1,
        series_id="7" * 64,
        accepted_observations=mixed_nonce["probe_observations"],
    ) is None


def test_seal_is_bound_to_test_case_attempt_and_complete_projection() -> None:
    sealed = _sealed_lineage(test_case_id=41, attempt_no=3)
    serialized = json.dumps(sealed)
    assert "7" * 64 not in serialized
    assert "series_id" not in sealed["integrity"]
    assert "series_id_fingerprint" in sealed["integrity"]
    assert normalize_runtime_lineage_evidence(
        sealed, test_case_id=41, attempt_no=3
    ) is not None
    assert normalize_runtime_lineage_evidence(
        sealed, test_case_id=42, attempt_no=3
    ) is None
    assert normalize_runtime_lineage_evidence(
        sealed, test_case_id=41, attempt_no=4
    ) is None
    assert normalize_runtime_lineage_evidence(sealed) is None
    assert normalize_runtime_lineage_evidence(
        sealed, test_case_id=True, attempt_no=3
    ) is None

    tampered = json.loads(json.dumps(sealed))
    tampered["summary"]["events_seen"] = 11
    assert normalize_runtime_lineage_evidence(
        tampered, test_case_id=41, attempt_no=3
    ) is None

    noncanonical_mac = json.loads(json.dumps(sealed))
    noncanonical_mac["integrity"]["mac"] = noncanonical_mac["integrity"]["mac"].upper()
    assert normalize_runtime_lineage_evidence(
        noncanonical_mac, test_case_id=41, attempt_no=3
    ) is None


def test_hex_shaped_input_secrets_are_hmac_projected() -> None:
    raw = _lineage_fixture()
    secret = "deadbeef" * 8
    raw["causal_flows"][0]["source_fingerprint"] = secret
    raw["causal_flows"][0]["candidate_id"] = _candidate_id(
        "url_param", secret, "innerhtml", "b" * 64
    )
    sealed = seal_runtime_lineage_probe_evidence(
        raw,
        test_case_id=2,
        attempt_no=1,
        series_id="7" * 64,
        accepted_observations=raw["probe_observations"],
    )

    assert sealed is not None
    assert secret not in json.dumps(sealed)

    tampered = json.loads(json.dumps(sealed))
    tampered["aab_observations"][2]["observation_fingerprint"] = "9" * 64
    assert normalize_runtime_lineage_evidence(
        tampered, test_case_id=2, attempt_no=1
    ) is None


def test_inconsistent_counters_limits_and_budgets_fail_closed() -> None:
    malformed_cases = []
    bad_event_sum = _lineage_fixture()
    bad_event_sum["summary"]["events_rejected"] = 1
    malformed_cases.append(bad_event_sum)
    bad_candidate_count = _lineage_fixture()
    bad_candidate_count["summary"]["candidates"] = 1
    malformed_cases.append(bad_candidate_count)
    bad_limit = _lineage_fixture()
    bad_limit["limits"]["ttl_ms"] = 4999
    malformed_cases.append(bad_limit)
    bad_flag = _lineage_fixture()
    bad_flag["limits"]["events_truncated"] = 1
    malformed_cases.append(bad_flag)
    bad_budget = _lineage_fixture()
    bad_budget["budget_exhausted"] = ["events"]
    malformed_cases.append(bad_budget)
    impossible_candidates = _lineage_fixture()
    impossible_candidates["summary"]["events_seen"] = 0
    impossible_candidates["summary"]["events_accepted"] = 0
    impossible_candidates["summary"]["events_rejected"] = 0
    malformed_cases.append(impossible_candidates)
    impossible_truncation = _lineage_fixture()
    impossible_truncation["limits"]["events_truncated"] = True
    impossible_truncation["budget_exhausted"] = ["events"]
    impossible_truncation["summary"]["events_seen"] = 12
    malformed_cases.append(impossible_truncation)

    assert all(normalize_runtime_lineage_evidence(item) is None for item in malformed_cases)


def test_structurally_incomplete_or_unknown_flows_are_rejected() -> None:
    for field in (
        "candidate_id",
        "source_category",
        "source_fingerprint",
        "sink_category",
        "sink_fingerprint",
    ):
        malformed = _lineage_fixture()
        malformed["value_influences"][0].pop(field)
        assert seal_runtime_lineage_probe_evidence(
            malformed,
            test_case_id=2,
            attempt_no=1,
            series_id="7" * 64,
            accepted_observations=malformed["probe_observations"],
        ) is None

    unknown_category = _lineage_fixture()
    unknown_category["value_influences"][0]["sink_category"] = "custom_sink"
    assert seal_runtime_lineage_probe_evidence(
        unknown_category,
        test_case_id=2,
        attempt_no=1,
        series_id="7" * 64,
        accepted_observations=unknown_category["probe_observations"],
    ) is None

    unknown_schema = _lineage_fixture()
    unknown_schema["schema_version"] = "runtime-causal-lineage/v999"
    assert normalize_runtime_lineage_evidence(unknown_schema) is None


def test_unhashable_schema_fields_fail_closed_without_raising() -> None:
    mutations = (
        ("schema_version", []),
        ("relation", []),
        ("source_category", {}),
        ("sink_category", []),
    )
    for field, hostile in mutations:
        value = _lineage_fixture()
        if field == "schema_version":
            value[field] = hostile
        else:
            value["value_influences"][0][field] = hostile
        assert seal_runtime_lineage_probe_evidence(
            value,
            test_case_id=2,
            attempt_no=1,
            series_id="7" * 64,
            accepted_observations=value["probe_observations"],
        ) is None

    hostile_arm = _lineage_fixture()
    hostile_arm["probe_observations"][0]["arm"] = []
    assert seal_runtime_lineage_probe_evidence(
        hostile_arm,
        test_case_id=2,
        attempt_no=1,
        series_id="7" * 64,
        accepted_observations=hostile_arm["probe_observations"],
    ) is None


def test_monitor_schema_exposes_sanitized_runtime_lineage() -> None:
    lineage = normalize_runtime_lineage_evidence(
        _sealed_lineage(), test_case_id=2, attempt_no=1
    )
    response = MonitorExecutionResponse(
        id=1,
        test_case_id=2,
        oracle_status="missed",
        duration_ms=25,
        executed_at=datetime.now(timezone.utc),
        runtime_lineage=lineage,
    )

    serialized = response.model_dump() if hasattr(response, "model_dump") else response.dict()
    assert serialized["runtime_lineage"]["summary"]["causal_only"] == 1
    assert serialized["runtime_lineage"]["summary"]["value_influence"] == 1
