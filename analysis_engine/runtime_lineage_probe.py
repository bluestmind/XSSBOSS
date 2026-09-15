"""Thread-safe, bounded coordination for inert runtime-lineage A/A/B probes.

The coordinator is deliberately passive: it returns probe metadata for a caller
to schedule and accepts source-free observations from an executor report.  It
does not perform browser or network work.  Probe strings contain an existing
alphanumeric marker plus a short alphanumeric suffix, and the repeated A arms
use the exact same string.

Only the exact A, A, B run sequence can complete a series.  Report summaries or
precomputed classifications are ignored; progression requires one strictly
validated observation matching the outstanding candidate, sink, run, arm, and
stimulus fingerprint.  Completed classification is limited to
``causal_only`` or ``value_influence``.  Because the fixed A, A, B sequence is
order-confounded, it is a prioritization signal rather than causal proof or a
vulnerability verdict.  Only the execution oracle confirms XSS.
"""
from __future__ import annotations

import hashlib
import math
import re
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping


SCHEMA_VERSION = "runtime-lineage-probe-coordinator/v1"
MAX_STATES = 32
STATE_TTL_SECONDS = 300.0
MAX_REPORT_OBSERVATIONS = 24
MAX_MARKER_CHARS = 64
ARM_SEQUENCE = ("A", "A", "B")

_SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_MARKER = re.compile(rf"^[A-Za-z0-9]{{1,{MAX_MARKER_CHARS}}}$")
_SAFE_FINGERPRINT = re.compile(r"^[0-9A-Fa-f]{64}$")
_SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _safe_fingerprint(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    return candidate if _SAFE_FINGERPRINT.fullmatch(candidate) else None


def _safe_key(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a safe identifier")
    candidate = value.strip()
    if not _SAFE_KEY.fullmatch(candidate):
        raise ValueError(f"{label} must be a safe identifier")
    return candidate


def _safe_marker(value: Any) -> str:
    if not isinstance(value, str) or not _SAFE_MARKER.fullmatch(value):
        raise ValueError(
            f"safe_marker must contain 1-{MAX_MARKER_CHARS} alphanumeric characters"
        )
    return value


def _required_fingerprint(value: Any, label: str) -> str:
    fingerprint = _safe_fingerprint(value)
    if fingerprint is None:
        raise ValueError(f"{label} must be a 64-character hexadecimal fingerprint")
    return fingerprint


def _bounded_positive_int(value: Any, *, maximum: int, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a positive integer")
    try:
        normalized = int(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(f"{label} must be a positive integer") from error
    if normalized <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return min(maximum, normalized)


def _bounded_positive_float(value: Any, *, maximum: float, label: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a positive number")
    try:
        normalized = float(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(f"{label} must be a positive number") from error
    if not math.isfinite(normalized) or normalized <= 0:
        raise ValueError(f"{label} must be a positive number")
    return min(maximum, normalized)


@dataclass(slots=True)
class _ProbeState:
    series_id: str
    candidate_id: str
    sink_fingerprint: str
    safe_marker: str
    variants: tuple[str, str]
    run_ids: tuple[str, str, str]
    expires_at: float
    observations: list[dict[str, Any]] = field(default_factory=list)
    conflicted: bool = False

    @property
    def next_index(self) -> int:
        return len(self.observations)

    @property
    def complete(self) -> bool:
        return self.next_index == len(ARM_SEQUENCE)


class RuntimeLineageProbeCoordinator:
    """Coordinate bounded inert A/A/B series without performing the probes."""

    SCHEMA_VERSION = SCHEMA_VERSION
    MAX_STATES = MAX_STATES
    STATE_TTL_SECONDS = STATE_TTL_SECONDS
    MAX_REPORT_OBSERVATIONS = MAX_REPORT_OBSERVATIONS

    def __init__(
        self,
        *,
        max_states: int = MAX_STATES,
        ttl_seconds: float = STATE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not callable(clock):
            raise ValueError("clock must be callable")
        self.max_states = _bounded_positive_int(
            max_states,
            maximum=MAX_STATES,
            label="max_states",
        )
        self.ttl_seconds = _bounded_positive_float(
            ttl_seconds,
            maximum=STATE_TTL_SECONDS,
            label="ttl_seconds",
        )
        self.max_report_observations = _bounded_positive_int(
            self.MAX_REPORT_OBSERVATIONS,
            maximum=MAX_REPORT_OBSERVATIONS,
            label="max_report_observations",
        )
        self._clock = clock
        self._lock = threading.RLock()
        self._states: OrderedDict[str, _ProbeState] = OrderedDict()

    def _now(self) -> float:
        try:
            current = float(self._clock())
        except (TypeError, ValueError, OverflowError) as error:
            raise RuntimeError("clock returned an invalid value") from error
        if not math.isfinite(current):
            raise RuntimeError("clock returned an invalid value")
        return current

    @staticmethod
    def _series_id(probe_key: str, candidate_id: str) -> str:
        return _fingerprint(f"runtime-lineage-probe|{probe_key}|{candidate_id}")

    @staticmethod
    def _variants(safe_marker: str, candidate_id: str) -> tuple[str, str]:
        variants = (
            f"{safe_marker}A",
            f"{safe_marker}B",
        )
        if any(
            not variant.startswith(safe_marker)
            or not variant.isascii()
            or not variant.isalnum()
            for variant in variants
        ):
            raise ValueError("probe variants must be alphanumeric and retain the marker")
        return variants

    @staticmethod
    def _run_ids(series_id: str) -> tuple[str, str, str]:
        nonce = secrets.token_hex(8)
        prefix = f"rlp:{series_id[:16]}:{nonce}"
        return f"{prefix}:1", f"{prefix}:2", f"{prefix}:3"

    def _purge_expired(self, now: float) -> None:
        expired = [
            series_id
            for series_id, state in self._states.items()
            if state.expires_at <= now
        ]
        for series_id in expired:
            self._states.pop(series_id, None)

    def _limits(self) -> dict[str, Any]:
        return {
            "max_states": self.max_states,
            "ttl_seconds": self.ttl_seconds,
            "max_report_observations": self.max_report_observations,
            "runs_per_series": len(ARM_SEQUENCE),
        }

    @staticmethod
    def _history(state: _ProbeState) -> list[dict[str, Any]]:
        return [dict(observation) for observation in state.observations]

    def _probe(self, state: _ProbeState) -> dict[str, Any]:
        index = state.next_index
        arm = ARM_SEQUENCE[index]
        stimulus = state.variants[0 if arm == "A" else 1]
        return {
            "run_id": state.run_ids[index],
            "arm": arm,
            "inert": True,
            "stimulus": stimulus,
            "stimulus_fingerprint": _fingerprint(stimulus),
        }

    def _probe_response(
        self,
        state: _ProbeState,
        *,
        status: str = "probe",
    ) -> dict[str, Any]:
        probe = self._probe(state)
        return {
            "schema_version": self.SCHEMA_VERSION,
            "status": status,
            "series_id": state.series_id,
            "candidate_id": state.candidate_id,
            "sink_fingerprint": state.sink_fingerprint,
            "next_arm": probe["arm"],
            "runtime_lineage_probe": probe,
            "runtime_lineage_observations": self._history(state),
            "limits": self._limits(),
        }

    def _complete_response(self, state: _ProbeState) -> dict[str, Any]:
        first_a, second_a, b_arm = state.observations
        stable_a = (
            first_a["stimulus_fingerprint"] == second_a["stimulus_fingerprint"]
            and first_a["observation_fingerprint"]
            == second_a["observation_fingerprint"]
        )
        b_changed = (
            b_arm["stimulus_fingerprint"] != first_a["stimulus_fingerprint"]
            and b_arm["observation_fingerprint"]
            != first_a["observation_fingerprint"]
        )
        if state.conflicted:
            stable_a = False
            b_changed = False
        classification = "value_influence" if stable_a and b_changed else "causal_only"
        return {
            "schema_version": self.SCHEMA_VERSION,
            "status": "complete",
            "series_id": state.series_id,
            "candidate_id": state.candidate_id,
            "sink_fingerprint": state.sink_fingerprint,
            "classification": classification,
            "aab": {
                "pattern": "A/A/B",
                "runs": 3,
                "stable_a": stable_a,
                "b_changed": b_changed,
                "inert": True,
            },
            "runtime_lineage_observations": self._history(state),
            "limits": self._limits(),
        }

    def _state_response(self, state: _ProbeState) -> dict[str, Any]:
        return (
            self._complete_response(state)
            if state.complete
            else self._probe_response(state)
        )

    def begin(
        self,
        probe_key: str,
        candidate_id: str,
        sink_fingerprint: str,
        safe_marker: str,
    ) -> dict[str, Any]:
        """Create a series or return its current idempotent next step."""
        safe_probe_key = _safe_key(probe_key, "probe_key")
        safe_candidate = _required_fingerprint(candidate_id, "candidate_id")
        safe_sink = _required_fingerprint(sink_fingerprint, "sink_fingerprint")
        marker = _safe_marker(safe_marker)
        series_id = self._series_id(safe_probe_key, safe_candidate)

        with self._lock:
            now = self._now()
            self._purge_expired(now)
            state = self._states.get(series_id)
            if state is not None:
                if (
                    state.candidate_id != safe_candidate
                    or state.sink_fingerprint != safe_sink
                    or state.safe_marker != marker
                ):
                    raise ValueError("an active probe series cannot change identity or marker")
                self._states.move_to_end(series_id)
                return self._state_response(state)

            variants = self._variants(marker, safe_candidate)
            state = _ProbeState(
                series_id=series_id,
                candidate_id=safe_candidate,
                sink_fingerprint=safe_sink,
                safe_marker=marker,
                variants=variants,
                run_ids=self._run_ids(series_id),
                expires_at=now + self.ttl_seconds,
            )
            self._states[series_id] = state
            while len(self._states) > self.max_states:
                self._states.popitem(last=False)
            return self._probe_response(state)

    def _candidate_observations(
        self,
        report: Any,
        *,
        state: _ProbeState,
    ) -> list[dict[str, Any]]:
        if not isinstance(report, Mapping):
            return []
        raw_observations = report.get("probe_observations")
        if not isinstance(raw_observations, list):
            return []

        observations: list[dict[str, Any]] = []
        for raw in raw_observations[:self.max_report_observations]:
            if not isinstance(raw, Mapping):
                continue
            # Other candidates may legitimately share a run ID because the
            # executor observes every bounded flow in one browser run.
            candidate = _safe_fingerprint(raw.get("candidate_id"))
            if candidate != state.candidate_id:
                continue
            sink = _safe_fingerprint(raw.get("sink_fingerprint"))
            run_id = raw.get("run_id")
            arm = raw.get("arm")
            stimulus = _safe_fingerprint(raw.get("stimulus_fingerprint"))
            observed = _safe_fingerprint(raw.get("observation_fingerprint"))
            if (
                raw.get("inert") is not True
                or not isinstance(run_id, str)
                or not _SAFE_RUN_ID.fullmatch(run_id)
                or not isinstance(arm, str)
                or arm not in {"A", "B"}
                or sink is None
                or stimulus is None
                or observed is None
            ):
                continue
            if sink != state.sink_fingerprint or run_id not in state.run_ids:
                continue
            run_index = state.run_ids.index(run_id)
            expected_arm = ARM_SEQUENCE[run_index]
            expected_stimulus = state.variants[0 if expected_arm == "A" else 1]
            if arm != expected_arm or stimulus != _fingerprint(expected_stimulus):
                continue
            observations.append({
                "run_id": run_id,
                "arm": arm,
                "inert": True,
                "candidate_id": candidate,
                "sink_fingerprint": sink,
                "stimulus_fingerprint": stimulus,
                "observation_fingerprint": observed,
            })
        return observations

    @staticmethod
    def _has_conflict(
        state: _ProbeState,
        observations: list[dict[str, Any]],
    ) -> bool:
        accepted = {
            item["run_id"]: item["observation_fingerprint"]
            for item in state.observations
        }
        observed_by_run: dict[str, set[str]] = {}
        for item in observations:
            observed_by_run.setdefault(item["run_id"], set()).add(
                item["observation_fingerprint"]
            )
        if any(len(fingerprints) > 1 for fingerprints in observed_by_run.values()):
            return True
        return any(
            run_id in accepted and next(iter(fingerprints)) != accepted[run_id]
            for run_id, fingerprints in observed_by_run.items()
            if fingerprints
        )

    def accept_report(
        self,
        probe_key: str,
        candidate_id: str,
        report: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Accept the outstanding observation and return the next step/evidence."""
        safe_probe_key = _safe_key(probe_key, "probe_key")
        safe_candidate = _required_fingerprint(candidate_id, "candidate_id")
        series_id = self._series_id(safe_probe_key, safe_candidate)

        with self._lock:
            now = self._now()
            self._purge_expired(now)
            state = self._states.get(series_id)
            if state is None:
                return {
                    "schema_version": self.SCHEMA_VERSION,
                    "status": "missing",
                    "series_id": series_id,
                    "candidate_id": safe_candidate,
                    "limits": self._limits(),
                }
            self._states.move_to_end(series_id)
            candidate_observations = self._candidate_observations(
                report,
                state=state,
            )
            if self._has_conflict(state, candidate_observations):
                state.conflicted = True
            if state.complete:
                return self._complete_response(state)

            expected_probe = self._probe(state)
            matches = [
                item for item in candidate_observations
                if item["run_id"] == expected_probe["run_id"]
            ]
            if len(matches) != 1:
                return self._probe_response(state, status="awaiting_observation")

            state.observations.append(matches[0])
            return self._state_response(state)

    def status(self, probe_key: str, candidate_id: str) -> dict[str, Any]:
        """Return current state without accepting observations or renewing TTL."""
        safe_probe_key = _safe_key(probe_key, "probe_key")
        safe_candidate = _required_fingerprint(candidate_id, "candidate_id")
        series_id = self._series_id(safe_probe_key, safe_candidate)
        with self._lock:
            now = self._now()
            self._purge_expired(now)
            state = self._states.get(series_id)
            if state is None:
                return {
                    "schema_version": self.SCHEMA_VERSION,
                    "status": "missing",
                    "series_id": series_id,
                    "candidate_id": safe_candidate,
                    "limits": self._limits(),
                }
            self._states.move_to_end(series_id)
            return self._state_response(state)

    @property
    def size(self) -> int:
        """Return the number of unexpired series currently retained."""
        with self._lock:
            now = self._now()
            self._purge_expired(now)
            return len(self._states)


__all__ = [
    "ARM_SEQUENCE",
    "MAX_MARKER_CHARS",
    "MAX_REPORT_OBSERVATIONS",
    "MAX_STATES",
    "SCHEMA_VERSION",
    "STATE_TTL_SECONDS",
    "RuntimeLineageProbeCoordinator",
]
