"""Authenticate, validate, and redact runtime-lineage evidence.

Runtime browser telemetry is treated as untrusted until this boundary verifies
the analyzer's exact bounds and internal relationships.  Public normalization
accepts raw causal-ordering evidence, but an inert A/A/B value-influence claim
must arrive as a worker-sealed projection bound to its test case and attempt.

Every persisted fingerprint is an HMAC projection with a field-specific domain.
The complete projection is then authenticated.  This prevents a raw 64-hex
secret, ephemeral event ID, run ID, URL, value, or unknown field from becoming a
storage channel while keeping equality relationships useful for prioritization.
The HMAC authenticates what the trusted worker validated and projected; it does
not certify hostile-page telemetry as truthful or prove XSS.  A fixed-order A/A/B
result also remains order-confounded.  Only the execution oracle confirms XSS.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, Dict, Optional

from analysis_engine.runtime_lineage import (
    MAX_CANDIDATES,
    MAX_DEPTH,
    MAX_EVENTS,
    MAX_OBSERVATIONS,
    MAX_RUNS,
    SINK_CATEGORIES,
    SOURCE_CATEGORIES,
    TTL_MS,
)
from backend_api.config import settings


_SAFE_FINGERPRINT = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_COORDINATOR_RUN_ID = re.compile(
    r"^rlp:(?P<series>[0-9a-f]{16}):(?P<nonce>[0-9a-f]{16}):(?P<index>[123])$"
)
_SAFE_KEY_VERSION = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
_RELATIONS = frozenset({"direct", "async"})
_URL_PROBE_SOURCES = frozenset({
    "document_uri",
    "document_url",
    "location_hash",
    "location_href",
    "location_search",
    "navigation_state",
    "url",
    "url_fragment",
    "url_param",
    "url_param_index",
    "url_query",
})
_SUMMARY_KEYS = (
    "events_seen",
    "events_accepted",
    "events_rejected",
    "observations_seen",
    "observations_accepted",
    "observations_rejected",
    "candidates",
    "causal_only",
    "value_influence",
)
_EXPECTED_LIMITS = {
    "max_depth": MAX_DEPTH,
    "ttl_ms": TTL_MS,
    "max_events": MAX_EVENTS,
    "max_candidates": MAX_CANDIDATES,
    "max_observations": MAX_OBSERVATIONS,
    "max_runs": MAX_RUNS,
}
_TRUNCATION_FLAGS = {
    "events_truncated": "events",
    "candidates_truncated": "candidates",
    "observations_truncated": "observations",
    "runs_truncated": "runs",
}
_PROJECTION_VERSION = "runtime-lineage-hmac-projection/v1"
_INTEGRITY_SCHEMA = "runtime-lineage-integrity/v1"
_SANITIZED_SCOPE = "causal-sanitized"
_PROBE_SCOPE = "aab-probe"
# This literal is part of the authenticated projection schema. Keep richer trust
# boundary wording in documentation unless a versioned projection migration is
# introduced; changing it would invalidate already-persisted signed evidence.
_INTERPRETATION = (
    "Runtime lineage is bounded prioritization evidence; only the execution "
    "oracle confirms XSS."
)


def _canonical_json(value: Any) -> Optional[str]:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError):
        return None


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _integrity_key() -> Optional[bytes]:
    secret = getattr(settings, "SECRET_KEY", None)
    if type(secret) is not str or not secret:
        return None
    return hmac.new(
        secret.encode("utf-8"),
        b"xssboss/runtime-lineage/integrity-key/v1",
        hashlib.sha256,
    ).digest()


def _key_version() -> Optional[str]:
    value = getattr(settings, "RUNTIME_LINEAGE_HMAC_KEY_VERSION", "1")
    if type(value) is not str:
        return None
    value = value.strip()
    return value if _SAFE_KEY_VERSION.fullmatch(value) else None


def _safe_fingerprint(value: Any) -> Optional[str]:
    if type(value) is not str:
        return None
    candidate = value.strip().lower()
    return candidate if _SAFE_FINGERPRINT.fullmatch(candidate) else None


def _strict_int(value: Any, *, minimum: int, maximum: int) -> Optional[int]:
    if type(value) is not int or value < minimum or value > maximum:
        return None
    return value


def _normalize_limits(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping):
        return None
    limits: Dict[str, Any] = {}
    for key, expected in _EXPECTED_LIMITS.items():
        if type(value.get(key)) is not int or value.get(key) != expected:
            return None
        limits[key] = expected
    for key in _TRUNCATION_FLAGS:
        flag = value.get(key)
        if type(flag) is not bool:
            return None
        limits[key] = flag
    return limits


def _normalize_summary(value: Any) -> Optional[Dict[str, int]]:
    if not isinstance(value, Mapping) or not all(key in value for key in _SUMMARY_KEYS):
        return None
    maxima = {
        "events_seen": MAX_EVENTS,
        "events_accepted": MAX_EVENTS,
        "events_rejected": MAX_EVENTS,
        "observations_seen": MAX_OBSERVATIONS,
        "observations_accepted": MAX_OBSERVATIONS,
        "observations_rejected": MAX_OBSERVATIONS,
        "candidates": MAX_CANDIDATES,
        "causal_only": MAX_CANDIDATES,
        "value_influence": MAX_CANDIDATES,
    }
    summary: Dict[str, int] = {}
    for key in _SUMMARY_KEYS:
        normalized = _strict_int(value.get(key), minimum=0, maximum=maxima[key])
        if normalized is None:
            return None
        summary[key] = normalized
    if summary["events_accepted"] + summary["events_rejected"] != summary["events_seen"]:
        return None
    if (
        summary["observations_accepted"] + summary["observations_rejected"]
        != summary["observations_seen"]
    ):
        return None
    if summary["causal_only"] + summary["value_influence"] != summary["candidates"]:
        return None
    return summary


def _summary_is_analyzer_possible(
    summary: Mapping[str, int],
    limits: Mapping[str, Any],
) -> bool:
    accepted_events = summary["events_accepted"]
    maximum_pairs = (accepted_events // 2) * (accepted_events - accepted_events // 2)
    if summary["candidates"] > maximum_pairs:
        return False
    if summary["value_influence"] * 3 > summary["observations_accepted"]:
        return False
    if limits["events_truncated"] and summary["events_seen"] != MAX_EVENTS:
        return False
    if limits["observations_truncated"] and summary["observations_seen"] != MAX_OBSERVATIONS:
        return False
    if limits["candidates_truncated"] and summary["candidates"] != MAX_CANDIDATES:
        return False
    # With equal 24-observation and 24-run caps, the production analyzer cannot
    # encounter a 25th distinct accepted run.
    if limits["runs_truncated"]:
        return False
    return True


def _candidate_id(
    source_category: str,
    source_fingerprint: str,
    sink_category: str,
    sink_fingerprint: str,
) -> str:
    metadata = {
        "source_category": source_category,
        "source_fingerprint": source_fingerprint,
        "sink_category": sink_category,
        "sink_fingerprint": sink_fingerprint,
    }
    canonical = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _valid_aab_metadata(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("pattern") == "A/A/B"
        and type(value.get("runs")) is int
        and value.get("runs") == 3
        and value.get("stable_a") is True
        and value.get("b_changed") is True
        and value.get("inert") is True
    )


def _normalize_flow(value: Any, classification: str) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping):
        return None
    relation = value.get("relation")
    if (
        value.get("classification") != classification
        or type(relation) is not str
        or relation not in _RELATIONS
    ):
        return None
    source_category = value.get("source_category")
    sink_category = value.get("sink_category")
    if (
        type(source_category) is not str
        or type(sink_category) is not str
        or source_category not in SOURCE_CATEGORIES
        or sink_category not in SINK_CATEGORIES
    ):
        return None
    source_fingerprint = _safe_fingerprint(value.get("source_fingerprint"))
    sink_fingerprint = _safe_fingerprint(value.get("sink_fingerprint"))
    candidate_id = _safe_fingerprint(value.get("candidate_id"))
    if not all((source_fingerprint, sink_fingerprint, candidate_id)):
        return None
    if candidate_id != _candidate_id(
        source_category,
        source_fingerprint,
        sink_category,
        sink_fingerprint,
    ):
        return None
    depth = _strict_int(value.get("depth"), minimum=1, maximum=MAX_DEPTH)
    latency_ms = _strict_int(value.get("latency_ms"), minimum=0, maximum=TTL_MS)
    if depth is None or latency_ms is None:
        return None
    if classification == "value_influence" and not _valid_aab_metadata(value.get("aab")):
        return None

    flow: Dict[str, Any] = {
        "candidate_id": candidate_id,
        "classification": classification,
        "source_category": source_category,
        "source_fingerprint": source_fingerprint,
        "sink_category": sink_category,
        "sink_fingerprint": sink_fingerprint,
        "relation": relation,
        "depth": depth,
        "latency_ms": latency_ms,
    }
    if classification == "value_influence":
        flow["aab"] = {
            "pattern": "A/A/B",
            "runs": 3,
            "stable_a": True,
            "b_changed": True,
            "inert": True,
        }
    return flow


def _normalize_flows(
    value: Mapping[str, Any],
    summary: Mapping[str, int],
) -> Optional[tuple[list[Dict[str, Any]], list[Dict[str, Any]]]]:
    raw_causal = value.get("causal_flows")
    raw_value = value.get("value_influences")
    if not isinstance(raw_causal, list) or not isinstance(raw_value, list):
        return None
    if (
        len(raw_causal) != summary["causal_only"]
        or len(raw_value) != summary["value_influence"]
        or len(raw_causal) + len(raw_value) != summary["candidates"]
    ):
        return None
    causal_flows: list[Dict[str, Any]] = []
    value_influences: list[Dict[str, Any]] = []
    for raw in raw_causal:
        flow = _normalize_flow(raw, "causal_only")
        if flow is None:
            return None
        causal_flows.append(flow)
    for raw in raw_value:
        flow = _normalize_flow(raw, "value_influence")
        if flow is None:
            return None
        value_influences.append(flow)
    candidate_ids = [flow["candidate_id"] for flow in causal_flows + value_influences]
    if len(set(candidate_ids)) != len(candidate_ids):
        return None
    return causal_flows, value_influences


def _normalize_budget(value: Any, limits: Mapping[str, Any]) -> Optional[list[str]]:
    if not isinstance(value, list) or len(value) > 5:
        return None
    allowed = set(_TRUNCATION_FLAGS.values()) | {"browser_events"}
    if any(type(item) is not str or item not in allowed for item in value):
        return None
    if len(set(value)) != len(value):
        return None
    exhausted = set(value)
    for flag, code in _TRUNCATION_FLAGS.items():
        if (code in exhausted) is not limits[flag]:
            return None
    return list(value)


def _normalize_collection(
    value: Any,
    budget_exhausted: Sequence[str],
) -> Optional[Dict[str, int]]:
    if "browser_events" not in budget_exhausted:
        return {}
    if not isinstance(value, Mapping):
        return None
    dropped = _strict_int(
        value.get("browser_dropped_events"),
        minimum=1,
        maximum=1_000_000,
    )
    if dropped is None:
        return None
    return {"browser_dropped_events": dropped}


def _normalize_observation(value: Any, *, projected: bool) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping) or value.get("inert") is not True:
        return None
    if projected:
        if "run_id" in value:
            return None
        run_id_fingerprint = _safe_fingerprint(value.get("run_id_fingerprint"))
    else:
        if "run_id_fingerprint" in value:
            return None
        run_id = value.get("run_id")
        if type(run_id) is not str or _SAFE_RUN_ID.fullmatch(run_id) is None:
            return None
        run_id_fingerprint = _sha256(run_id)
    arm = value.get("arm")
    if type(arm) is not str or arm not in {"A", "B"}:
        return None
    candidate_id = _safe_fingerprint(value.get("candidate_id"))
    sink_fingerprint = _safe_fingerprint(value.get("sink_fingerprint"))
    stimulus_fingerprint = _safe_fingerprint(value.get("stimulus_fingerprint"))
    observation_fingerprint = _safe_fingerprint(value.get("observation_fingerprint"))
    if not all((
        run_id_fingerprint,
        candidate_id,
        sink_fingerprint,
        stimulus_fingerprint,
        observation_fingerprint,
    )):
        return None
    return {
        "run_id_fingerprint": run_id_fingerprint,
        "arm": arm,
        "inert": True,
        "candidate_id": candidate_id,
        "sink_fingerprint": sink_fingerprint,
        "stimulus_fingerprint": stimulus_fingerprint,
        "observation_fingerprint": observation_fingerprint,
    }


def _stable_aab(observations: list[Dict[str, Any]]) -> bool:
    if len(observations) != 3 or [item["arm"] for item in observations] != ["A", "A", "B"]:
        return False
    if len({item["run_id_fingerprint"] for item in observations}) != 3:
        return False
    first_a, second_a, b_arm = observations
    return (
        first_a["stimulus_fingerprint"] == second_a["stimulus_fingerprint"]
        and first_a["observation_fingerprint"] == second_a["observation_fingerprint"]
        and b_arm["stimulus_fingerprint"] != first_a["stimulus_fingerprint"]
        and b_arm["observation_fingerprint"] != first_a["observation_fingerprint"]
    )


def _coordinator_history_matches(series_id: Any, observations: Any) -> bool:
    """Require the exact run identifiers emitted by one coordinator series."""
    normalized_series = _safe_fingerprint(series_id)
    if (
        normalized_series is None
        or series_id != normalized_series
        or not isinstance(observations, list)
        or len(observations) != 3
    ):
        return False
    nonce: Optional[str] = None
    for index, raw in enumerate(observations, start=1):
        if not isinstance(raw, Mapping):
            return False
        run_id = raw.get("run_id")
        if type(run_id) is not str:
            return False
        match = _COORDINATOR_RUN_ID.fullmatch(run_id)
        if (
            match is None
            or match.group("series") != normalized_series[:16]
            or match.group("index") != str(index)
        ):
            return False
        if nonce is None:
            nonce = match.group("nonce")
        elif match.group("nonce") != nonce:
            return False
    return True


def _normalize_aab_proof(
    value: Mapping[str, Any],
    summary: Mapping[str, int],
    causal_flows: list[Dict[str, Any]],
    value_influences: list[Dict[str, Any]],
    *,
    projected: bool,
) -> Optional[list[Dict[str, Any]]]:
    key = "aab_observations" if projected else "probe_observations"
    wrong_key = "probe_observations" if projected else "aab_observations"
    if wrong_key in value:
        return None
    if not value_influences:
        return None if projected and key in value else []
    raw_observations = value.get(key)
    if not isinstance(raw_observations, list) or len(raw_observations) > MAX_OBSERVATIONS:
        return None
    if not projected and len(raw_observations) != summary["observations_accepted"]:
        return None
    if len(raw_observations) > summary["observations_accepted"]:
        return None
    observations: list[Dict[str, Any]] = []
    for raw in raw_observations:
        observation = _normalize_observation(raw, projected=projected)
        if observation is None:
            return None
        observations.append(observation)

    flow_sinks = {
        flow["candidate_id"]: flow["sink_fingerprint"]
        for flow in causal_flows + value_influences
    }
    if any(
        flow_sinks.get(item["candidate_id"]) != item["sink_fingerprint"]
        for item in observations
    ):
        return None
    proof: list[Dict[str, Any]] = []
    for flow in value_influences:
        matching = [
            item for item in observations
            if item["candidate_id"] == flow["candidate_id"]
            and item["sink_fingerprint"] == flow["sink_fingerprint"]
        ]
        if not _stable_aab(matching):
            return None
        proof.extend(matching)
    if len(proof) != 3 * len(value_influences):
        return None
    return proof


def _normalize_core(value: Mapping[str, Any], *, projected: bool) -> Optional[Dict[str, Any]]:
    schema = value.get("schema_version")
    allowed_schemas = {"runtime-causal-lineage/v1"} if projected else {
        "runtime-causal-lineage/v1", "1.0",
    }
    if type(schema) is not str or schema not in allowed_schemas:
        return None
    limits = _normalize_limits(value.get("limits"))
    summary = _normalize_summary(value.get("summary"))
    if limits is None or summary is None or not _summary_is_analyzer_possible(summary, limits):
        return None
    flows = _normalize_flows(value, summary)
    if flows is None:
        return None
    causal_flows, value_influences = flows
    budget_exhausted = _normalize_budget(value.get("budget_exhausted"), limits)
    if budget_exhausted is None:
        return None
    collection = _normalize_collection(value.get("collection"), budget_exhausted)
    if collection is None:
        return None
    aab_observations = _normalize_aab_proof(
        value,
        summary,
        causal_flows,
        value_influences,
        projected=projected,
    )
    if aab_observations is None:
        return None
    normalized: Dict[str, Any] = {
        "schema_version": "runtime-causal-lineage/v1",
        "available": True,
        "value_free": True,
        "interpretation": _INTERPRETATION,
        "limits": limits,
        "budget_exhausted": budget_exhausted,
        "summary": summary,
        "causal_flows": causal_flows,
        "value_influences": value_influences,
    }
    if aab_observations:
        normalized["aab_observations"] = aab_observations
        normalized["probe_runs"] = 3
    if collection:
        normalized["collection"] = collection
    return normalized


def _project_fingerprint(domain: str, value: str) -> Optional[str]:
    key = _integrity_key()
    if key is None:
        return None
    return hmac.new(
        key,
        f"{_PROJECTION_VERSION}|{domain}|{value}".encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def _project_core(value: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    projected: Dict[str, Any] = {
        "schema_version": value["schema_version"],
        "projection_version": _PROJECTION_VERSION,
        "available": True,
        "value_free": True,
        "interpretation": value["interpretation"],
        "limits": dict(value["limits"]),
        "budget_exhausted": list(value["budget_exhausted"]),
        "summary": dict(value["summary"]),
        "causal_flows": [],
        "value_influences": [],
    }
    candidate_map: dict[str, str] = {}
    sink_map: dict[str, str] = {}
    for list_name in ("causal_flows", "value_influences"):
        for flow in value[list_name]:
            source_fp = _project_fingerprint("source-structure", flow["source_fingerprint"])
            sink_fp = _project_fingerprint("sink-structure", flow["sink_fingerprint"])
            if source_fp is None or sink_fp is None:
                return None
            candidate_id = _candidate_id(
                flow["source_category"],
                source_fp,
                flow["sink_category"],
                sink_fp,
            )
            candidate_map[flow["candidate_id"]] = candidate_id
            sink_map[flow["sink_fingerprint"]] = sink_fp
            projected_flow = {
                **flow,
                "candidate_id": candidate_id,
                "source_fingerprint": source_fp,
                "sink_fingerprint": sink_fp,
            }
            projected[list_name].append(projected_flow)
    if "aab_observations" in value:
        projected_observations = []
        for item in value["aab_observations"]:
            fields = {
                "run_id_fingerprint": _project_fingerprint(
                    "probe-run", item["run_id_fingerprint"]
                ),
                "stimulus_fingerprint": _project_fingerprint(
                    "probe-stimulus", item["stimulus_fingerprint"]
                ),
                "observation_fingerprint": _project_fingerprint(
                    "sink-observation", item["observation_fingerprint"]
                ),
            }
            if any(result is None for result in fields.values()):
                return None
            candidate_id = candidate_map.get(item["candidate_id"])
            sink_fingerprint = sink_map.get(item["sink_fingerprint"])
            if candidate_id is None or sink_fingerprint is None:
                return None
            projected_observations.append({
                "run_id_fingerprint": fields["run_id_fingerprint"],
                "arm": item["arm"],
                "inert": True,
                "candidate_id": candidate_id,
                "sink_fingerprint": sink_fingerprint,
                "stimulus_fingerprint": fields["stimulus_fingerprint"],
                "observation_fingerprint": fields["observation_fingerprint"],
            })
        projected["aab_observations"] = projected_observations
        projected["probe_runs"] = 3
    if "collection" in value:
        projected["collection"] = dict(value["collection"])
    return projected


def _sign_projection(
    payload: Mapping[str, Any],
    *,
    scope: str,
    test_case_id: Optional[int] = None,
    attempt_no: Optional[int] = None,
    series_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    canonical = _canonical_json(payload)
    key = _integrity_key()
    key_version = _key_version()
    bound_test_case = _strict_int(
        test_case_id, minimum=1, maximum=2_147_483_647
    )
    bound_attempt = _strict_int(
        attempt_no, minimum=1, maximum=2_147_483_647
    )
    if (
        canonical is None
        or key is None
        or key_version is None
        or bound_test_case is None
        or bound_attempt is None
    ):
        return None
    integrity: Dict[str, Any] = {
        "schema_version": _INTEGRITY_SCHEMA,
        "key_version": key_version,
        "scope": scope,
        "evidence_digest": hashlib.sha256(canonical.encode("ascii")).hexdigest(),
        "test_case_id": bound_test_case,
        "attempt_no": bound_attempt,
    }
    if scope == _PROBE_SCOPE:
        if _safe_fingerprint(series_id) is None:
            return None
        projected_series = _project_fingerprint("probe-series", str(series_id).lower())
        if projected_series is None:
            return None
        integrity.update({
            "series_id_fingerprint": projected_series,
        })
    elif scope != _SANITIZED_SCOPE:
        return None
    message = _canonical_json(integrity)
    if message is None:
        return None
    integrity["mac"] = hmac.new(key, message.encode("ascii"), hashlib.sha256).hexdigest()
    return {**dict(payload), "integrity": integrity}


def _verify_projection(
    value: Mapping[str, Any],
    *,
    test_case_id: Optional[int],
    attempt_no: Optional[int],
) -> Optional[tuple[Dict[str, Any], str]]:
    integrity = value.get("integrity")
    if not isinstance(integrity, Mapping):
        return None
    scope = integrity.get("scope")
    if type(scope) is not str or scope not in {_SANITIZED_SCOPE, _PROBE_SCOPE}:
        return None
    expected_keys = {
        "schema_version", "key_version", "scope", "evidence_digest", "mac",
        "test_case_id", "attempt_no",
    }
    if scope == _PROBE_SCOPE:
        expected_keys.add("series_id_fingerprint")
    if set(integrity.keys()) != expected_keys:
        return None
    if (
        integrity.get("schema_version") != _INTEGRITY_SCHEMA
        or integrity.get("key_version") != _key_version()
    ):
        return None
    digest = _safe_fingerprint(integrity.get("evidence_digest"))
    mac = _safe_fingerprint(integrity.get("mac"))
    key = _integrity_key()
    if (
        digest is None
        or mac is None
        or key is None
        or integrity.get("evidence_digest") != digest
        or integrity.get("mac") != mac
    ):
        return None
    payload = {key_name: item for key_name, item in value.items() if key_name != "integrity"}
    canonical = _canonical_json(payload)
    if canonical is None or hashlib.sha256(canonical.encode("ascii")).hexdigest() != digest:
        return None
    unsigned = dict(integrity)
    unsigned.pop("mac", None)
    message = _canonical_json(unsigned)
    if message is None:
        return None
    expected_mac = hmac.new(key, message.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected_mac):
        return None
    bound_test_case = _strict_int(
        integrity.get("test_case_id"), minimum=1, maximum=2_147_483_647
    )
    bound_attempt = _strict_int(
        integrity.get("attempt_no"), minimum=1, maximum=2_147_483_647
    )
    if (
        bound_test_case is None
        or bound_attempt is None
        or _strict_int(test_case_id, minimum=1, maximum=2_147_483_647) is None
        or _strict_int(attempt_no, minimum=1, maximum=2_147_483_647) is None
        or bound_test_case != test_case_id
        or bound_attempt != attempt_no
    ):
        return None
    if scope == _PROBE_SCOPE:
        series_fingerprint = _safe_fingerprint(
            integrity.get("series_id_fingerprint")
        )
        if (
            series_fingerprint is None
            or integrity.get("series_id_fingerprint") != series_fingerprint
        ):
            return None
    return payload, scope


def seal_runtime_lineage_probe_evidence(
    value: Any,
    *,
    test_case_id: int,
    attempt_no: int,
    series_id: str,
    accepted_observations: Any,
) -> Optional[Dict[str, Any]]:
    """Seal the worker's redacted A/A/B projection, not hostile-page truth.

    Verification proves projection integrity, binding, and coordinator history.
    The fixed-order observation remains order-confounded prioritization evidence;
    only the execution oracle confirms XSS.
    """
    if not isinstance(value, Mapping) or "projection_version" in value or "integrity" in value:
        return None
    normalized = _normalize_core(value, projected=False)
    if (
        normalized is None
        or normalized["summary"]["value_influence"] != 1
        or normalized["value_influences"][0]["source_category"]
        not in _URL_PROBE_SOURCES
    ):
        return None
    if not _coordinator_history_matches(series_id, accepted_observations):
        return None
    accepted = []
    for raw in accepted_observations:
        observation = _normalize_observation(raw, projected=False)
        if observation is None:
            return None
        accepted.append(observation)
    if accepted != normalized.get("aab_observations"):
        return None
    projected = _project_core(normalized)
    if projected is None:
        return None
    return _sign_projection(
        projected,
        scope=_PROBE_SCOPE,
        test_case_id=test_case_id,
        attempt_no=attempt_no,
        series_id=series_id,
    )


def normalize_runtime_lineage_evidence(
    value: Any,
    *,
    test_case_id: Optional[int] = None,
    attempt_no: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """Return an authenticated value-free projection or ``None``.

    Raw value-influence objects are deliberately rejected.  Only
    :func:`seal_runtime_lineage_probe_evidence` may introduce that stronger
    classification, after the coordinator supplies its exact accepted history.
    """
    if not isinstance(value, Mapping):
        return None
    if "projection_version" in value or "integrity" in value:
        if value.get("projection_version") != _PROJECTION_VERSION:
            return None
        verified = _verify_projection(
            value,
            test_case_id=test_case_id,
            attempt_no=attempt_no,
        )
        if verified is None:
            return None
        payload, scope = verified
        normalized = _normalize_core(payload, projected=True)
        if normalized is None:
            return None
        rebuilt = {**normalized, "projection_version": _PROJECTION_VERSION}
        # Authentication covers the entire canonical projection. Reject signed
        # objects containing fields the value-free schema would otherwise drop.
        if _canonical_json(rebuilt) != _canonical_json(payload):
            return None
        has_value = normalized["summary"]["value_influence"] > 0
        if (scope == _PROBE_SCOPE) is not has_value:
            return None
        return {**rebuilt, "integrity": dict(value["integrity"])}

    normalized = _normalize_core(value, projected=False)
    if normalized is None or normalized["summary"]["value_influence"] > 0:
        return None
    projected = _project_core(normalized)
    if projected is None:
        return None
    return _sign_projection(
        projected,
        scope=_SANITIZED_SCOPE,
        test_case_id=test_case_id,
        attempt_no=attempt_no,
    )


def classify_runtime_lineage(
    value: Any,
    *,
    test_case_id: Optional[int] = None,
    attempt_no: Optional[int] = None,
) -> Optional[str]:
    """Return the strongest authenticated lineage class, if any."""
    normalized = normalize_runtime_lineage_evidence(
        value,
        test_case_id=test_case_id,
        attempt_no=attempt_no,
    )
    if normalized is None:
        return None
    if normalized["summary"]["value_influence"] > 0:
        return "value_influence"
    if normalized["summary"]["causal_only"] > 0:
        return "causal_only"
    return None


__all__ = [
    "classify_runtime_lineage",
    "normalize_runtime_lineage_evidence",
    "seal_runtime_lineage_probe_evidence",
]
