"""Bounded, source-free runtime causal lineage and inert A/A/B analysis.

The module accepts normalized runtime metadata rather than browser objects.  It
correlates a source event with a later sink event only when both occur in the
same execution context or along an explicitly observed parent-context chain.
That establishes causal ordering, not value flow.  A candidate is upgraded to
``value_influence`` only when an inert A/A/B experiment is deterministic for
the repeated A arm and changes the observation at the same structural sink for
the B arm.  The fixed A, A, B order is not randomized or counterbalanced, so the
result remains order-confounded prioritization evidence.  Neither classification
proves value flow or script execution; only the execution oracle confirms XSS.

Only allowlisted identifiers, categories, fingerprints, and bounded numeric
metadata are exported.  Input fields such as values, source text, URLs,
filenames, and stack frames are never copied into the result.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from itertools import islice
from typing import Any, Iterable, Mapping


MAX_DEPTH = 8
TTL_MS = 5_000
MAX_EVENTS = 256
MAX_CANDIDATES = 8
MAX_OBSERVATIONS = 24
MAX_RUNS = 24

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_FINGERPRINT = re.compile(r"^[0-9A-Fa-f]{64}$")
_TOKEN_SEPARATORS = re.compile(r"[.\-\s]+")

# Categories are intentionally finite.  Aliases are normalized by replacing
# dots, hyphens, and whitespace with underscores and then lower-casing.
SOURCE_CATEGORIES = frozenset({
    "attribute",
    "broadcast_channel",
    "cookie",
    "dataset",
    "document_uri",
    "document_url",
    "dom_input",
    "event_data",
    "fetch_response",
    "form_input",
    "indexed_db",
    "location_hash",
    "location_href",
    "location_search",
    "message_data",
    "navigation_state",
    "network_response",
    "postmessage",
    "referrer",
    "service_worker_message",
    "session_storage",
    "storage",
    "url",
    "url_fragment",
    "url_param",
    "url_param_index",
    "url_query",
    "user_input",
    "websocket_message",
    "window_name",
    "worker_message",
    "xhr_response",
})

SINK_CATEGORIES = frozenset({
    "attribute",
    "document_write",
    "eval",
    "function_ctor",
    "iframe_src",
    "innerhtml",
    "insertadjacenthtml",
    "jquery_html",
    "jquery_selector",
    "location",
    "location_assign",
    "location_href",
    "location_replace",
    "navigation",
    "outerhtml",
    "postmessage",
    "range_fragment",
    "script_src",
    "script_text",
    "set_href_attr",
    "setattribute",
    "srcdoc",
    "style",
    "timer_string",
    "window_open",
})

_SOURCE_ALIASES = {
    "document_baseuri": "url",
    "document_cookie": "cookie",
    "document_documenturi": "document_uri",
    "document_referrer": "referrer",
    "document_urlunencoded": "document_url",
    "event_message_data": "message_data",
    "local_storage": "storage",
    "localstorage": "storage",
    "location_pathname": "navigation_state",
    "message": "message_data",
    "post_message": "postmessage",
    "sessionstorage": "session_storage",
    "url_search_params": "url_param",
    "websocket": "websocket_message",
    "xhr": "xhr_response",
}

_SINK_ALIASES = {
    "document_writeln": "document_write",
    "function": "function_ctor",
    "html": "innerhtml",
    "insert_adjacent_html": "insertadjacenthtml",
    "location_write": "navigation",
    "set_attribute": "setattribute",
    "set_interval_string": "timer_string",
    "set_timeout_string": "timer_string",
    "window_location": "navigation",
}


def _bounded_items(values: Any, maximum: int) -> tuple[list[Any], bool]:
    """Read at most ``maximum + 1`` items, including from generators."""
    if values is None:
        return [], False
    if isinstance(values, (str, bytes, bytearray, Mapping)):
        return [], False
    try:
        sampled = list(islice(iter(values), maximum + 1))
    except TypeError:
        return [], False
    return sampled[:maximum], len(sampled) > maximum


def _safe_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    return candidate if _SAFE_ID.fullmatch(candidate) else None


def _safe_fingerprint(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    return candidate if _SAFE_FINGERPRINT.fullmatch(candidate) else None


def _timestamp_ms(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(numeric) or numeric < 0 or numeric > 9_000_000_000_000_000:
        return None
    if not numeric.is_integer():
        return None
    return int(numeric)


def _category(value: Any, *, kind: str) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or len(raw) > 80 or not raw.isascii():
        return None
    normalized = _TOKEN_SEPARATORS.sub("_", raw).lower().strip("_")
    aliases = _SOURCE_ALIASES if kind == "source" else _SINK_ALIASES
    allowed = SOURCE_CATEGORIES if kind == "source" else SINK_CATEGORIES
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in allowed else None


def _first(record: Mapping[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        if name in record and record.get(name) is not None:
            return record.get(name)
    return None


@dataclass(frozen=True, slots=True)
class _RuntimeEvent:
    kind: str
    entity_id: str
    category: str
    fingerprint: str
    context_id: str
    parent_context_id: str | None
    linked_source_id: str | None
    timestamp_ms: int
    relation: str
    lineage_depth: int
    order: int


@dataclass(frozen=True, slots=True)
class _Observation:
    run_id: str
    arm: str
    candidate_id: str | None
    source_id: str | None
    sink_id: str | None
    sink_fingerprint: str
    stimulus_fingerprint: str
    observation_fingerprint: str
    order: int


@dataclass(frozen=True, slots=True)
class _Candidate:
    candidate_id: str
    source_id: str
    source_category: str
    source_fingerprint: str
    source_context_id: str
    sink_id: str
    sink_category: str
    sink_fingerprint: str
    sink_context_id: str
    relation: str
    depth: int
    latency_ms: int
    source_order: int
    sink_order: int

    def to_dict(self, classification: str) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "classification": classification,
            "source_id": self.source_id,
            "source_category": self.source_category,
            "source_fingerprint": self.source_fingerprint,
            "source_context_id": self.source_context_id,
            "sink_id": self.sink_id,
            "sink_category": self.sink_category,
            "sink_fingerprint": self.sink_fingerprint,
            "sink_context_id": self.sink_context_id,
            "relation": self.relation,
            "depth": self.depth,
            "latency_ms": self.latency_ms,
        }


def _normalize_event(
    record: Any,
    order: int,
    *,
    max_depth: int = MAX_DEPTH,
) -> _RuntimeEvent | None:
    if not isinstance(record, Mapping):
        return None
    kind_raw = record.get("kind")
    if not isinstance(kind_raw, str):
        return None
    kind = kind_raw.strip().lower()
    if kind not in {"source", "sink"}:
        return None

    category_value = _first(
        record,
        (f"{kind}_category", "category", kind),
    )
    category = _category(category_value, kind=kind)
    entity_id = _safe_id(_first(record, (f"{kind}_id", "event_id")))
    fingerprint = _safe_fingerprint(_first(
        record,
        (f"{kind}_fingerprint", "stack_fingerprint", "fingerprint"),
    ))
    context_names = (
        ("source_context_id", "context_id", "async_context_id")
        if kind == "source"
        else ("sink_context_id", "context_id", "async_context_id")
    )
    context_id = _safe_id(_first(record, context_names))
    parent_value = _first(
        record,
        ("parent_context_id", "parent_async_context_id"),
    )
    # A sink may state the originating context directly.  For an async edge it
    # is equivalent to a parent-context relationship.
    if (
        parent_value is None
        and kind == "sink"
        and record.get("source_context_id") is not None
    ):
        stated_source_context = _safe_id(record.get("source_context_id"))
        if stated_source_context is None:
            parent_value = record.get("source_context_id")
        elif stated_source_context != context_id:
            parent_value = stated_source_context
    parent_context_id = None if parent_value is None else _safe_id(parent_value)
    timestamp = _timestamp_ms(_first(record, ("ts_ms", "timestamp_ms")))
    depth_value = record.get("depth")
    if depth_value is None:
        lineage_depth = 0
    else:
        normalized_depth = _timestamp_ms(depth_value)
        if normalized_depth is None or normalized_depth > max_depth:
            return None
        lineage_depth = normalized_depth

    relation_raw = record.get("relation")
    if relation_raw is None:
        relation = "async" if parent_context_id else "direct"
    elif isinstance(relation_raw, str):
        relation = relation_raw.strip().lower()
    else:
        return None
    if relation not in {"direct", "async"}:
        return None

    if not all((category, entity_id, fingerprint, context_id)) or timestamp is None:
        return None
    if parent_value is not None and parent_context_id is None:
        return None
    if parent_context_id == context_id:
        return None

    linked_source_id: str | None = None
    if kind == "sink" and record.get("source_id") is not None:
        linked_source_id = _safe_id(record.get("source_id"))
        if linked_source_id is None:
            return None

    return _RuntimeEvent(
        kind=kind,
        entity_id=entity_id,
        category=category,
        fingerprint=fingerprint,
        context_id=context_id,
        parent_context_id=parent_context_id,
        linked_source_id=linked_source_id,
        timestamp_ms=timestamp,
        relation=relation,
        lineage_depth=lineage_depth,
        order=order,
    )


def _normalize_observation(record: Any, order: int) -> _Observation | None:
    if not isinstance(record, Mapping) or record.get("inert") is not True:
        return None
    run_id = _safe_id(record.get("run_id"))
    arm_raw = _first(record, ("arm", "variant"))
    arm = arm_raw.strip().upper() if isinstance(arm_raw, str) else ""
    if not run_id or arm not in {"A", "B"}:
        return None

    candidate_raw = record.get("candidate_id")
    candidate_id = None if candidate_raw is None else _safe_fingerprint(candidate_raw)
    source_raw = record.get("source_id")
    sink_raw = record.get("sink_id")
    source_id = None if source_raw is None else _safe_id(source_raw)
    sink_id = None if sink_raw is None else _safe_id(sink_raw)
    if candidate_raw is not None and candidate_id is None:
        return None
    if source_raw is not None and source_id is None:
        return None
    if sink_raw is not None and sink_id is None:
        return None
    if candidate_id is None and not (source_id and sink_id):
        return None

    sink_fingerprint = _safe_fingerprint(record.get("sink_fingerprint"))
    stimulus_fingerprint = _safe_fingerprint(_first(
        record,
        ("stimulus_fingerprint", "input_fingerprint", "probe_fingerprint"),
    ))
    observation_fingerprint = _safe_fingerprint(_first(
        record,
        ("observation_fingerprint", "result_fingerprint", "value_fingerprint"),
    ))
    if not all((sink_fingerprint, stimulus_fingerprint, observation_fingerprint)):
        return None
    return _Observation(
        run_id=run_id,
        arm=arm,
        candidate_id=candidate_id,
        source_id=source_id,
        sink_id=sink_id,
        sink_fingerprint=sink_fingerprint,
        stimulus_fingerprint=stimulus_fingerprint,
        observation_fingerprint=observation_fingerprint,
        order=order,
    )


def _candidate_id(source: _RuntimeEvent, sink: _RuntimeEvent) -> str:
    metadata = {
        "source_category": source.category,
        "source_fingerprint": source.fingerprint,
        "sink_category": sink.category,
        "sink_fingerprint": sink.fingerprint,
    }
    canonical = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _build_candidates(
    events: list[_RuntimeEvent],
    *,
    max_depth: int = MAX_DEPTH,
    ttl_ms: int = TTL_MS,
) -> list[_Candidate]:
    sources: dict[str, list[_RuntimeEvent]] = {}
    parents: dict[str, str] = {}
    candidates: dict[tuple[str, ...], _Candidate] = {}

    parent_options: dict[str, set[str]] = {}
    for event in events:
        if event.parent_context_id:
            parent_options.setdefault(event.context_id, set()).add(
                event.parent_context_id
            )
    ambiguous_contexts = {
        context for context, options in parent_options.items() if len(options) > 1
    }

    # Sorting by runtime time prevents a later input record from being treated
    # as a predecessor merely because the caller supplied records out of order.
    for event in sorted(events, key=lambda item: (item.timestamp_ms, item.order)):
        parent = event.parent_context_id
        if parent and event.context_id not in ambiguous_contexts:
            parents.setdefault(event.context_id, parent)

        if event.kind == "source":
            sources.setdefault(event.context_id, []).append(event)
            continue

        contexts: list[tuple[str, int]] = []
        seen_contexts: set[str] = set()
        context = event.context_id
        hops = 0
        while context and context not in seen_contexts and hops < max_depth:
            contexts.append((context, hops))
            seen_contexts.add(context)
            if context in ambiguous_contexts:
                break
            context = parents.get(context, "")
            hops += 1

        for source_context, context_hops in contexts:
            for source in sources.get(source_context, ()):
                depth = max(
                    context_hops + 1,
                    event.lineage_depth,
                    source.lineage_depth,
                )
                if event.linked_source_id and source.entity_id != event.linked_source_id:
                    continue
                latency = event.timestamp_ms - source.timestamp_ms
                if latency < 0 or latency > ttl_ms:
                    continue
                candidate = _Candidate(
                    candidate_id=_candidate_id(source, event),
                    source_id=source.entity_id,
                    source_category=source.category,
                    source_fingerprint=source.fingerprint,
                    source_context_id=source.context_id,
                    sink_id=event.entity_id,
                    sink_category=event.category,
                    sink_fingerprint=event.fingerprint,
                    sink_context_id=event.context_id,
                    relation=(
                        "async"
                        if context_hops or source.relation == "async" or event.relation == "async"
                        else "direct"
                    ),
                    depth=depth,
                    latency_ms=latency,
                    source_order=source.order,
                    sink_order=event.order,
                )
                key = (candidate.candidate_id,)
                prior = candidates.get(key)
                if prior is None or (
                    candidate.depth,
                    candidate.latency_ms,
                    candidate.sink_order,
                    candidate.source_order,
                ) < (
                    prior.depth,
                    prior.latency_ms,
                    prior.sink_order,
                    prior.source_order,
                ):
                    candidates[key] = candidate

    return sorted(
        candidates.values(),
        key=lambda item: (
            item.sink_order,
            item.depth,
            item.latency_ms,
            item.source_order,
            item.candidate_id,
        ),
    )


def _observation_assignments(
    candidates: list[_Candidate],
    observations: list[_Observation],
) -> dict[str, list[_Observation]]:
    assigned: dict[str, list[_Observation]] = {
        candidate.candidate_id: [] for candidate in candidates
    }
    for observation in observations:
        matches = [
            candidate for candidate in candidates
            if observation.sink_fingerprint == candidate.sink_fingerprint
            and (
                observation.source_id is None
                or observation.source_id == candidate.source_id
            )
            and (
                observation.sink_id is None
                or observation.sink_id == candidate.sink_id
            )
            and (
                observation.candidate_id == candidate.candidate_id
                if observation.candidate_id is not None
                else (
                    observation.source_id == candidate.source_id
                    and observation.sink_id == candidate.sink_id
                )
            )
        ]
        # An observation without a candidate ID must not upgrade two structurally
        # distinct flows that happen to reuse the same source/sink identifiers.
        if len(matches) == 1:
            assigned[matches[0].candidate_id].append(observation)
    return assigned


def _stable_aab(observations: list[_Observation]) -> bool:
    ordered = sorted(observations, key=lambda item: item.order)
    if len(ordered) != 3 or [item.arm for item in ordered] != ["A", "A", "B"]:
        return False
    if len({item.run_id for item in ordered}) != 3:
        return False
    first_a, second_a, b_arm = ordered
    if len({item.sink_fingerprint for item in ordered}) != 1:
        return False
    if first_a.stimulus_fingerprint != second_a.stimulus_fingerprint:
        return False
    if first_a.observation_fingerprint != second_a.observation_fingerprint:
        return False
    if b_arm.stimulus_fingerprint == first_a.stimulus_fingerprint:
        return False
    return b_arm.observation_fingerprint != first_a.observation_fingerprint


class RuntimeLineageAnalyzer:
    """Correlate bounded runtime metadata without claiming execution."""

    SCHEMA_VERSION = "runtime-causal-lineage/v1"
    MAX_DEPTH = MAX_DEPTH
    TTL_MS = TTL_MS
    MAX_EVENTS = MAX_EVENTS
    MAX_CANDIDATES = MAX_CANDIDATES
    MAX_OBSERVATIONS = MAX_OBSERVATIONS
    MAX_RUNS = MAX_RUNS

    @classmethod
    def analyze(
        cls,
        events: Iterable[Mapping[str, Any]] | None,
        observations: Iterable[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        max_depth = max(1, min(MAX_DEPTH, int(cls.MAX_DEPTH)))
        ttl_ms = max(0, min(TTL_MS, int(cls.TTL_MS)))
        max_events = max(0, min(MAX_EVENTS, int(cls.MAX_EVENTS)))
        max_candidates = max(0, min(MAX_CANDIDATES, int(cls.MAX_CANDIDATES)))
        max_observations = max(
            0, min(MAX_OBSERVATIONS, int(cls.MAX_OBSERVATIONS))
        )
        max_runs = max(0, min(MAX_RUNS, int(cls.MAX_RUNS)))

        event_items, events_truncated = _bounded_items(events, max_events)
        normalized_events = [
            event for index, item in enumerate(event_items)
            if (
                event := _normalize_event(item, index, max_depth=max_depth)
            ) is not None
        ]

        observation_items, observations_truncated = _bounded_items(
            observations, max_observations
        )
        normalized_observations: list[_Observation] = []
        run_ids: set[str] = set()
        runs_truncated = False
        for index, item in enumerate(observation_items):
            observation = _normalize_observation(item, index)
            if observation is None:
                continue
            if observation.run_id not in run_ids and len(run_ids) >= max_runs:
                runs_truncated = True
                continue
            run_ids.add(observation.run_id)
            normalized_observations.append(observation)

        all_candidates = _build_candidates(
            normalized_events,
            max_depth=max_depth,
            ttl_ms=ttl_ms,
        )
        candidates_truncated = len(all_candidates) > max_candidates
        candidates = all_candidates[:max_candidates]
        assignments = _observation_assignments(candidates, normalized_observations)

        causal_flows: list[dict[str, Any]] = []
        value_influences: list[dict[str, Any]] = []
        for candidate in candidates:
            candidate_observations = assignments.get(candidate.candidate_id, [])
            if _stable_aab(candidate_observations):
                record = candidate.to_dict("value_influence")
                record["aab"] = {
                    "pattern": "A/A/B",
                    "runs": 3,
                    "stable_a": True,
                    "b_changed": True,
                    "inert": True,
                }
                value_influences.append(record)
            else:
                causal_flows.append(candidate.to_dict("causal_only"))

        budget_exhausted: list[str] = []
        if events_truncated:
            budget_exhausted.append("events")
        if candidates_truncated:
            budget_exhausted.append("candidates")
        if observations_truncated:
            budget_exhausted.append("observations")
        if runs_truncated:
            budget_exhausted.append("runs")

        return {
            "schema_version": cls.SCHEMA_VERSION,
            "interpretation": (
                "Causal ordering or inert value influence only; script execution "
                "and vulnerability are not established."
            ),
            "limits": {
                "max_depth": max_depth,
                "ttl_ms": ttl_ms,
                "max_events": max_events,
                "max_candidates": max_candidates,
                "max_observations": max_observations,
                "max_runs": max_runs,
                "events_truncated": events_truncated,
                "candidates_truncated": candidates_truncated,
                "observations_truncated": observations_truncated,
                "runs_truncated": runs_truncated,
            },
            "budget_exhausted": budget_exhausted,
            "summary": {
                "events_seen": len(event_items),
                "events_accepted": len(normalized_events),
                "events_rejected": len(event_items) - len(normalized_events),
                "observations_seen": len(observation_items),
                "observations_accepted": len(normalized_observations),
                "observations_rejected": (
                    len(observation_items) - len(normalized_observations)
                ),
                "candidates": len(candidates),
                "causal_only": len(causal_flows),
                "value_influence": len(value_influences),
            },
            "causal_flows": causal_flows,
            "value_influences": value_influences,
        }


def analyze(
    events: Iterable[Mapping[str, Any]] | None,
    observations: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Public functional wrapper for :meth:`RuntimeLineageAnalyzer.analyze`."""
    return RuntimeLineageAnalyzer.analyze(events, observations)


__all__ = [
    "MAX_CANDIDATES",
    "MAX_DEPTH",
    "MAX_EVENTS",
    "MAX_OBSERVATIONS",
    "MAX_RUNS",
    "SINK_CATEGORIES",
    "SOURCE_CATEGORIES",
    "TTL_MS",
    "RuntimeLineageAnalyzer",
    "analyze",
]
