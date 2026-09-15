"""
Log serializer and parser utility.
Provides fast JSON serialization and robust parsing with backwards-compatible fallbacks.
"""
from __future__ import annotations

import ast
import json
from collections import deque
from collections.abc import Mapping
from typing import Any, Dict

from backend_api.utils.runtime_lineage_evidence import (
    normalize_runtime_lineage_evidence,
)


_RUNTIME_LINEAGE_KEYS = ("runtime_lineage", "runtime_causal_lineage")
_RUNTIME_LINEAGE_KEY_SET = frozenset(
    key.casefold() for key in _RUNTIME_LINEAGE_KEYS
)
_UNPARSED_LOG_DIAGNOSTIC = "[unparsed execution log omitted]"
_UNSAFE_CONTAINER_DIAGNOSTIC = "[nested execution log data omitted]"
_MAX_LOG_CONTAINER_DEPTH = 64


def _is_runtime_lineage_key(key: Any) -> bool:
    return type(key) is str and str.casefold(key) in _RUNTIME_LINEAGE_KEY_SET


def _scrub_nested_runtime_lineage(
    value: Any,
    *,
    depth: int = 0,
    active_container_ids: set[int] | None = None,
) -> Any:
    """Copy JSON-like data while dropping lineage aliases at every depth."""
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    is_mapping = isinstance(value, Mapping)
    is_sequence = isinstance(value, (list, tuple, deque))
    if not is_mapping and not is_sequence:
        return _UNSAFE_CONTAINER_DIAGNOSTIC
    if depth >= _MAX_LOG_CONTAINER_DEPTH:
        return _UNSAFE_CONTAINER_DIAGNOSTIC

    active = active_container_ids if active_container_ids is not None else set()
    container_id = id(value)
    if container_id in active:
        return _UNSAFE_CONTAINER_DIAGNOSTIC
    active.add(container_id)
    try:
        if is_mapping:
            return {
                key: _scrub_nested_runtime_lineage(
                    nested,
                    depth=depth + 1,
                    active_container_ids=active,
                )
                for key, nested in value.items()
                if type(key) is str and not _is_runtime_lineage_key(key)
            }
        scrubbed = [
            _scrub_nested_runtime_lineage(
                nested,
                depth=depth + 1,
                active_container_ids=active,
            )
            for nested in value
        ]
        return tuple(scrubbed) if isinstance(value, tuple) else scrubbed
    finally:
        active.remove(container_id)


def safe_unparsed_execution_log_text(raw_logs: Any) -> str:
    """Return a constant diagnostic for non-empty logs that could not be parsed.

    A failed mapping parse cannot locate and normalize nested evidence reliably.
    Raw unparsed text is therefore never exposed or persisted at evidence
    boundaries.
    """
    if raw_logs is None:
        return ""
    text = str(raw_logs)
    if not text:
        return ""
    return _UNPARSED_LOG_DIAGNOSTIC


def sanitize_execution_logs(
    logs_dict: Any,
    *,
    test_case_id: int | None = None,
    attempt_no: int | None = None,
) -> Dict[str, Any]:
    """Return a copy whose runtime-lineage evidence is safe to persist.

    Browser logs are an input boundary.  Remove both accepted lineage aliases
    before validating either value, then retain at most one canonical,
    value-free ``runtime_lineage`` projection.  Other log fields are preserved
    and the caller's dictionary is never mutated.
    """
    if not isinstance(logs_dict, Mapping):
        return {}

    sanitized = {}
    raw_candidates = []
    for key, value in logs_dict.items():
        if type(key) is not str:
            continue
        if _is_runtime_lineage_key(key):
            raw_candidates.append(value)
            continue
        sanitized[key] = _scrub_nested_runtime_lineage(value)

    for raw_lineage in raw_candidates:
        try:
            normalized = normalize_runtime_lineage_evidence(
                raw_lineage,
                test_case_id=test_case_id,
                attempt_no=attempt_no,
            )
        except Exception:
            # Malformed or future producer data must fail closed at persistence.
            normalized = None
        if isinstance(normalized, dict):
            sanitized["runtime_lineage"] = normalized
            break

    return sanitized


def parse_execution_logs(raw_logs: Any) -> Dict[str, Any]:
    """
    Safely parse execution logs.
    Prioritizes JSON parsing and provides graceful fallback for legacy Python dict string reprs.
    """
    if not raw_logs:
        return {}
    if isinstance(raw_logs, dict):
        return raw_logs
    if not isinstance(raw_logs, str):
        return {}

    # 1. Primary: Standard JSON parser
    try:
        data = json.loads(raw_logs)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, TypeError):
        pass

    # 2. Secondary fallback: AST literal parser for legacy records
    try:
        data = ast.literal_eval(raw_logs)
        if isinstance(data, dict):
            return data
    except (ValueError, SyntaxError, MemoryError, TypeError):
        pass

    return {}


def serialize_execution_logs(
    logs_dict: Dict[str, Any],
    *,
    test_case_id: int | None = None,
    attempt_no: int | None = None,
) -> str:
    """
    Serialize logs dictionary to standard JSON string format.
    """
    try:
        return json.dumps(
            sanitize_execution_logs(
                logs_dict,
                test_case_id=test_case_id,
                attempt_no=attempt_no,
            ),
            default=lambda _value: _UNSAFE_CONTAINER_DIAGNOSTIC,
        )
    except Exception:
        return "{}"


__all__ = [
    "parse_execution_logs",
    "safe_unparsed_execution_log_text",
    "sanitize_execution_logs",
    "serialize_execution_logs",
]
