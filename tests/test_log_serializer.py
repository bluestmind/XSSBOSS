"""Persistence-boundary tests for browser execution logs."""
from __future__ import annotations

import hashlib
import json
from collections import UserDict, deque
from types import MappingProxyType

from backend_api.utils.log_serializer import (
    parse_execution_logs,
    safe_unparsed_execution_log_text,
    sanitize_execution_logs,
    serialize_execution_logs,
)
from backend_api.utils.runtime_lineage_evidence import (
    seal_runtime_lineage_probe_evidence,
)


def _candidate_id(
    source_category: str,
    source_fingerprint: str,
    sink_category: str,
    sink_fingerprint: str,
) -> str:
    canonical = json.dumps(
        {
            "source_category": source_category,
            "source_fingerprint": source_fingerprint,
            "sink_category": sink_category,
            "sink_fingerprint": sink_fingerprint,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _raw_value_influence() -> dict:
    candidate_id = _candidate_id("url_param", "a" * 64, "innerhtml", "b" * 64)
    return {
        "schema_version": "runtime-causal-lineage/v1",
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
        },
        "budget_exhausted": [],
        "summary": {
            "events_seen": 2,
            "events_accepted": 2,
            "events_rejected": 0,
            "observations_seen": 3,
            "observations_accepted": 3,
            "observations_rejected": 0,
            "candidates": 1,
            "causal_only": 0,
            "value_influence": 1,
        },
        "causal_flows": [],
        "value_influences": [
            {
                "candidate_id": candidate_id,
                "classification": "value_influence",
                "source_id": "SOURCE-ID-SECRET",
                "source_category": "url_param",
                "source_fingerprint": "a" * 64,
                "sink_id": "SINK-ID-SECRET",
                "sink_category": "innerhtml",
                "sink_fingerprint": "b" * 64,
                "relation": "direct",
                "depth": 1,
                "latency_ms": 1,
                "raw_value": "LINEAGE-VALUE-SECRET",
                "aab": {
                    "pattern": "A/A/B",
                    "runs": 3,
                    "stable_a": True,
                    "b_changed": True,
                    "inert": True,
                },
            }
        ],
        "probe_observations": [
            {
                "run_id": "rlp:7777777777777777:0123456789abcdef:1",
                "arm": "A",
                "inert": True,
                "candidate_id": candidate_id,
                "sink_fingerprint": "b" * 64,
                "stimulus_fingerprint": "c" * 64,
                "observation_fingerprint": "d" * 64,
            },
            {
                "run_id": "rlp:7777777777777777:0123456789abcdef:2",
                "arm": "A",
                "inert": True,
                "candidate_id": candidate_id,
                "sink_fingerprint": "b" * 64,
                "stimulus_fingerprint": "c" * 64,
                "observation_fingerprint": "d" * 64,
            },
            {
                "run_id": "rlp:7777777777777777:0123456789abcdef:3",
                "arm": "B",
                "inert": True,
                "candidate_id": candidate_id,
                "sink_fingerprint": "b" * 64,
                "stimulus_fingerprint": "e" * 64,
                "observation_fingerprint": "f" * 64,
            },
        ],
        "secret": "ROOT-LINEAGE-SECRET",
    }


def _sealed_value_influence() -> dict:
    raw = _raw_value_influence()
    sealed = seal_runtime_lineage_probe_evidence(
        raw,
        test_case_id=17,
        attempt_no=2,
        series_id="7" * 64,
        accepted_observations=raw["probe_observations"],
    )
    assert sealed is not None
    return sealed


def test_sanitize_execution_logs_canonicalizes_without_mutating_input() -> None:
    raw_lineage = _sealed_value_influence()
    logs = {
        "console": ["unrelated log stays"],
        "network": {"status": 200},
        "runtime_causal_lineage": raw_lineage,
    }

    sanitized = sanitize_execution_logs(
        logs, test_case_id=17, attempt_no=2
    )

    assert sanitized["console"] == ["unrelated log stays"]
    assert sanitized["network"] == {"status": 200}
    assert "runtime_causal_lineage" not in sanitized
    assert sanitized["runtime_lineage"]["summary"]["value_influence"] == 1
    assert "runtime_causal_lineage" in logs
    assert logs["runtime_causal_lineage"] is raw_lineage

    persisted = json.dumps(sanitized)
    for raw_secret in (
        "SOURCE-ID-SECRET",
        "SINK-ID-SECRET",
        "RAW-RUN-ID-A1",
        "RAW-RUN-ID-A2",
        "RAW-RUN-ID-B",
        "LINEAGE-VALUE-SECRET",
        "ROOT-LINEAGE-SECRET",
    ):
        assert raw_secret not in persisted
    assert "run_id_fingerprint" in persisted


def test_serialize_execution_logs_always_applies_lineage_boundary() -> None:
    logs = {
        "errors": [],
        "runtime_lineage": _sealed_value_influence(),
    }

    persisted = serialize_execution_logs(
        logs, test_case_id=17, attempt_no=2
    )
    parsed = parse_execution_logs(persisted)

    assert parsed["errors"] == []
    assert parsed["runtime_lineage"]["summary"]["value_influence"] == 1
    assert "SOURCE-ID-SECRET" not in persisted
    assert "RAW-RUN-ID-A1" not in persisted
    assert "probe_observations" not in parsed["runtime_lineage"]


def test_invalid_lineage_aliases_are_removed_and_other_logs_survive() -> None:
    logs = {
        "console": ["keep me"],
        "duration": 17,
        "runtime_lineage": {"schema_version": "forged", "secret": "CANONICAL"},
        "runtime_causal_lineage": {"run_id": "RAW-RUN", "secret": "LEGACY"},
    }

    sanitized = sanitize_execution_logs(logs)
    persisted = serialize_execution_logs(logs)

    assert sanitized == {"console": ["keep me"], "duration": 17}
    assert parse_execution_logs(persisted) == sanitized
    assert "runtime_lineage" not in persisted
    assert "runtime_causal_lineage" not in persisted
    assert "CANONICAL" not in persisted
    assert "LEGACY" not in persisted


def test_lineage_aliases_are_removed_recursively_and_case_insensitively() -> None:
    logs = {
        "Runtime_Lineage": _sealed_value_influence(),
        "errors": [
            {
                "message": "keep",
                "runtime_lineage": {
                    "raw_value": "NESTED-CANONICAL-SECRET",
                },
            },
            {
                "nested": {
                    "RUNTIME_CAUSAL_LINEAGE": {
                        "raw_value": "NESTED-LEGACY-SECRET",
                    },
                },
            },
        ],
    }

    sanitized = sanitize_execution_logs(logs, test_case_id=17, attempt_no=2)
    persisted = json.dumps(sanitized)

    assert sanitized["runtime_lineage"]["summary"]["value_influence"] == 1
    assert sanitized["errors"] == [{"message": "keep"}, {"nested": {}}]
    assert "Runtime_Lineage" not in sanitized
    assert "RUNTIME_CAUSAL_LINEAGE" not in persisted
    assert "NESTED-CANONICAL-SECRET" not in persisted
    assert "NESTED-LEGACY-SECRET" not in persisted


def test_non_string_mapping_keys_are_dropped_at_the_json_boundary() -> None:
    logs = {
        b"runtime_lineage": {
            "raw_value": "ROOT-BYTES-KEY-SECRET",
        },
        "nested": {
            b"runtime_causal_lineage": {
                "raw_value": "NESTED-BYTES-KEY-SECRET",
            },
            17: "NON-JSON-KEY-SECRET",
            "message": "keep",
        },
    }

    sanitized = sanitize_execution_logs(logs)
    persisted = json.dumps(sanitized)

    assert sanitized == {"nested": {"message": "keep"}}
    assert "BYTES-KEY-SECRET" not in persisted
    assert "NON-JSON-KEY-SECRET" not in persisted


def test_non_builtin_containers_cannot_stringify_lineage_around_the_boundary() -> None:
    class HostileStringKey(str):
        def casefold(self) -> str:
            return "ordinary_key"

    def hidden(secret: str) -> dict:
        return {
            "message": "keep",
            "runtime_lineage": {
                "classification": "value_influence",
                "raw_value": secret,
            },
        }

    logs = {
        "errors": [
            UserDict(hidden("USERDICT-RAW-SECRET")),
            MappingProxyType(hidden("MAPPINGPROXY-RAW-SECRET")),
            deque([hidden("DEQUE-RAW-SECRET")]),
        ],
        "unsupported": object(),
        HostileStringKey("runtime_lineage"): {
            "raw_value": "STRING-SUBCLASS-RAW-SECRET",
        },
    }

    persisted = serialize_execution_logs(logs)
    parsed = json.loads(persisted)

    assert parsed["errors"] == [
        {"message": "keep"},
        {"message": "keep"},
        [{"message": "keep"}],
    ]
    assert parsed["unsupported"] == "[nested execution log data omitted]"
    assert "RAW-SECRET" not in persisted


def test_unsealed_or_replayed_value_influence_is_removed() -> None:
    unsealed = sanitize_execution_logs({
        "console": ["keep"],
        "runtime_lineage": _raw_value_influence(),
    }, test_case_id=17, attempt_no=2)
    replayed = sanitize_execution_logs({
        "runtime_lineage": _sealed_value_influence(),
    }, test_case_id=18, attempt_no=2)

    assert unsealed == {"console": ["keep"]}
    assert replayed == {}


def test_all_unparsed_execution_log_text_is_omitted() -> None:
    malformed_json = (
        '{"runtime_lineage":{"classification":"value_influence",'
        '"raw_value":"LINEAGE-SECRET"}} trailing'
    )
    escaped_json = (
        r'{"runtime\u005flineage":{"classification":"value_influence",'
        r'"raw_value":"ESCAPED-JSON-SECRET"}} trailing'
    )
    escaped_python = (
        r"{'runtime\x5flineage': {'classification': 'value_influence', "
        r"'raw_value': 'ESCAPED-PYTHON-SECRET'}} trailing"
    )

    samples = (malformed_json, escaped_json, escaped_python, "legacy browser timeout")

    for sample in samples:
        safe = safe_unparsed_execution_log_text(sample)
        assert safe == "[unparsed execution log omitted]"
        assert "SECRET" not in safe
