"""Shared, bounded schema helpers for client-bundle research signals."""
from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Mapping, Tuple


SANITIZER_BOUNDARY_CATEGORIES = (
    "sanitizer_context_mismatch",
    "sanitizer_output_invalidated",
    "sanitizer_partial_coverage",
    "opaque_sanitizer_flow",
    "trusted_types_unvalidated_flow",
    "effective_sanitizer_boundary",
)
SANITIZER_BOUNDARY_FINDING_LIMIT = 100


def _safe_boundary_finding(item: Any) -> Dict[str, Any] | None:
    """Allowlist source-free structural fields before a recon signal is stored."""
    if not isinstance(item, dict):
        return None
    category = str(item.get("category") or "")[:80]
    if category not in SANITIZER_BOUNDARY_CATEGORIES:
        return None
    safe: Dict[str, Any] = {"category": category}
    string_fields = {
        "source_kind": 80,
        "source_param": 120,
        "sink_kind": 80,
        "required_context": 40,
        "transform_kind": 80,
        "protection_state": 40,
    }
    for key, limit in string_fields.items():
        if key not in item:
            continue
        value = str(item.get(key) or "")[:limit]
        if re.fullmatch(r"[A-Za-z0-9_$.[\]-]*", value):
            safe[key] = value
    for key in ("source_offset", "transform_offset", "sink_offset"):
        if key not in item:
            continue
        try:
            safe[key] = max(-1 if key == "transform_offset" else 0, min(10_000_000, int(item[key])))
        except (TypeError, ValueError, OverflowError):
            continue
    if "confidence" in item:
        try:
            confidence = float(item["confidence"])
            if math.isfinite(confidence):
                safe["confidence"] = max(0.0, min(1.0, confidence))
        except (TypeError, ValueError, OverflowError):
            pass
    fingerprint = str(item.get("fingerprint") or "")[:64].lower()
    if re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        safe["fingerprint"] = fingerprint
    reasons = item.get("reason_codes")
    if isinstance(reasons, list):
        safe["reason_codes"] = list(dict.fromkeys(
            str(reason)[:80]
            for reason in reasons[:20]
            if isinstance(reason, str) and re.fullmatch(r"[a-z0-9_]{1,80}", reason)
        ))
    details = item.get("details")
    if isinstance(details, dict):
        safe_details: Dict[str, Any] = {}
        try:
            safe_details["hops"] = max(0, min(8, int(details.get("hops", 0))))
        except (TypeError, ValueError, OverflowError):
            pass
        for key in ("compatible_context", "requires_dynamic_confirmation"):
            if isinstance(details.get(key), bool):
                safe_details[key] = details[key]
        policy_method = str(details.get("policy_method") or "")[:40]
        if re.fullmatch(r"create(?:HTML|Script|ScriptURL)", policy_method):
            safe_details["policy_method"] = policy_method
        if safe_details:
            safe["details"] = safe_details
    return safe


def bounded_sanitizer_boundary_evidence(
    analysis: Mapping[str, Any],
) -> Tuple[Dict[str, int], List[Dict[str, Any]]]:
    """Return the common bounded counts/findings shape used by recon producers."""
    raw_findings = analysis.get("sanitizer_boundary_findings")
    findings = [
        safe
        for item in (
            raw_findings[:SANITIZER_BOUNDARY_FINDING_LIMIT]
            if isinstance(raw_findings, (list, tuple))
            else []
        )
        if (safe := _safe_boundary_finding(item)) is not None
    ]
    summary = analysis.get("sanitizer_boundary_summary")
    if not isinstance(summary, dict):
        summary = {}

    counts: Dict[str, int] = {
        "sanitizer_boundary_findings": len(findings),
    }
    for category in SANITIZER_BOUNDARY_CATEGORIES:
        try:
            value = int(summary.get(category, 0) or 0)
        except (TypeError, ValueError, OverflowError):
            value = 0
        counts[category] = max(
            0,
            min(SANITIZER_BOUNDARY_FINDING_LIMIT, value),
        )
    return counts, findings
