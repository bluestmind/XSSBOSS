"""Hypothesis-driven research planning and evidence feedback.

This layer connects reconnaissance, payload selection, browser evidence, and
cross-run learning. It is deterministic and bounded: it never expands scope or
performs a destructive action, and every recommendation remains attached to an
authorized experiment.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections.abc import Mapping
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from backend_api.models.context import Context
from backend_api.models.endpoint import Endpoint
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.experiment import Experiment
from backend_api.models.filter_profile import FilterProfile
from backend_api.models.param import Param
from backend_api.models.research import (
    AttackSurfaceEdge,
    AttackSurfaceNode,
    ResearchHypothesis,
    ResearchObservation,
    ResearchTechniqueStat,
)
from backend_api.models.sink import Sink
from backend_api.models.test_case import TestCase
from backend_api.config import settings
from backend_api.services.run_state_service import RunStateService
from backend_api.utils.impact_scorer import ImpactScorer
from backend_api.utils.log_serializer import (
    parse_execution_logs,
    sanitize_execution_logs,
)
from backend_api.utils.logger import logger
from backend_api.utils.runtime_lineage_evidence import normalize_runtime_lineage_evidence
from fuzzer.strategy import Strategy


_SEMANTIC_HYPOTHESES = {
    "open_redirect": {
        "terms": {"redirect", "redirect_uri", "return", "returnto", "next", "continue", "dest", "destination"},
        "techniques": ["absolute-url", "scheme-relative", "parser-differential", "multi-encoding"],
        "confidence": 0.62,
    },
    "ssrf": {
        "terms": {"url", "uri", "webhook", "callback", "feed", "fetch", "proxy", "image", "avatar"},
        "techniques": ["oob-canary", "redirect-chain-canary", "url-parser-differential"],
        "confidence": 0.48,
    },
    "path_traversal": {
        "terms": {"file", "filename", "path", "folder", "dir", "directory", "template", "page", "download"},
        "techniques": ["relative-traversal-canary", "encoded-separator", "normalization-differential"],
        "confidence": 0.52,
    },
    "sqli": {
        "terms": {"id", "query", "search", "filter", "sort", "order", "where", "user", "account"},
        "techniques": ["syntax-differential", "boolean-differential", "time-safe-threshold"],
        "confidence": 0.38,
    },
    "idor_bola": {
        "terms": {"id", "user", "userid", "account", "accountid", "owner", "ownerid", "tenant", "team", "project", "order", "invoice"},
        "techniques": ["cross-identity-read", "cross-identity-write", "object-substitution", "role-boundary"],
        "confidence": 0.46,
    },
    "command_injection": {
        "terms": {"cmd", "command", "exec", "execute", "shell", "process", "host", "hostname", "ping", "utility"},
        "techniques": ["syntax-differential", "argument-boundary", "non-destructive-delay-canary"],
        "confidence": 0.34,
    },
    "file_upload": {
        "terms": {"file", "upload", "attachment", "avatar", "image", "import", "document", "filename"},
        "techniques": ["content-type-differential", "extension-normalization", "storage-origin", "authorization-boundary"],
        "confidence": 0.42,
    },
}

_CONTEXT_TECHNIQUES = {
    "HTML_TEXT": ["html-element", "svg-event", "parser-differential", "mXSS"],
    "ATTR_QUOTED": ["attribute-breakout", "event-handler", "entity-encoding"],
    "ATTR_UNQUOTED": ["unquoted-attribute", "whitespace-encoding", "event-handler"],
    "EVENT_HANDLER_ATTR": ["javascript-expression", "tagged-template", "encoding-differential"],
    "JS_STRING_LITERAL": ["js-string-breakout", "template-literal", "unicode-escape"],
    "JS_IDENTIFIER": ["javascript-expression", "constructor-chain", "unicode-escape"],
    "JSON_VALUE": ["json-script-breakout", "unicode-escape", "parser-differential"],
    "URL_QUERY": ["javascript-uri", "scheme-differential", "double-encoding"],
    "URL_FRAGMENT": ["dom-source-to-sink", "fragment-encoding", "postMessage"],
}

_SANITIZER_BOUNDARY_CATEGORIES = {
    "sanitizer_context_mismatch",
    "sanitizer_output_invalidated",
    "sanitizer_partial_coverage",
    "opaque_sanitizer_flow",
    "trusted_types_unvalidated_flow",
    "effective_sanitizer_boundary",
}
_RISKY_SANITIZER_BOUNDARY_CATEGORIES = (
    _SANITIZER_BOUNDARY_CATEGORIES - {"effective_sanitizer_boundary"}
)
_SANITIZER_SOURCE_KINDS = {
    "url_param", "url_param_index", "location_hash", "location_search",
    "location_href", "referrer", "window_name", "postmessage", "cookie",
    "storage",
}
_SANITIZER_SINK_KINDS = {
    "innerHTML", "insertAdjacentHTML", "document_write", "eval",
    "function_ctor", "timer_string", "navigation", "jquery_html",
    "jquery_selector", "srcdoc", "iframe_src", "range_fragment",
    "set_href_attr", "set_event_attr",
}
_SANITIZER_CONTEXTS = {
    "HTML", "SCRIPT", "URL", "CSS", "SCRIPT_URL", "URL_COMPONENT",
    "URL_SYNTAX", "NUMERIC",
}
_SANITIZER_TRANSFORMS = {
    "dompurify", "url_component_encoding", "url_encoding", "css_escape",
    "numeric_coercion", "trusted_types_policy", "custom_transform", "none",
    "non_dominating_transform",
}
_SANITIZER_PROTECTION_STATES = {
    "unprotected", "effective", "ineffective", "invalidated", "unknown",
}
_SANITIZER_REASON_CODES = {
    "dynamic_or_relaxed_configuration", "known_transform",
    "policy_uses_known_sanitizer", "opaque_policy_method",
    "identity_policy_method", "content_preserving_policy_method",
    "unknown_policy_method", "unverified_custom_transform",
    "opaque_post_transform", "source_outside_transform",
    "mixed_with_external_value", "output_context_mismatch",
    "unprotected_sink_path", "alternative_unprotected_path",
    "content_preserving_wrapper",
}
_SANITIZER_POLICY_METHODS = {"createHTML", "createScript", "createScriptURL"}


class ResearchService:
    @staticmethod
    def _fingerprint(*parts: Any) -> str:
        normalized = "|".join("" if part is None else str(part) for part in parts)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    @staticmethod
    def _safe_artifact_url(value: Any) -> str:
        """Normalize stored artifact labels while dropping URL-carried secrets."""
        try:
            parsed = urlparse(str(value or ""))
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                return ""
            hostname = parsed.hostname
            if ":" in hostname and not hostname.startswith("["):
                hostname = f"[{hostname}]"
            netloc = hostname
            if parsed.port is not None:
                netloc = f"{netloc}:{parsed.port}"
            return parsed._replace(
                scheme=parsed.scheme.lower(),
                netloc=netloc,
                params="",
                query="",
                fragment="",
            ).geturl()
        except (TypeError, ValueError):
            return ""

    @staticmethod
    def _safe_route_path(value: Any) -> str:
        try:
            return (urlparse(str(value or "")[:2000]).path.rstrip("/") or "/")[:500]
        except (TypeError, ValueError):
            return ""

    @staticmethod
    def _bounded_int(value: Any, maximum: int, default: int = 0) -> int:
        try:
            return max(0, min(maximum, int(value)))
        except (TypeError, ValueError, OverflowError):
            return default

    @staticmethod
    def _bounded_float(value: Any, maximum: float = 1.0, default: float = 0.0) -> float:
        try:
            parsed = float(value)
            if not math.isfinite(parsed):
                return default
            return max(0.0, min(maximum, parsed))
        except (TypeError, ValueError, OverflowError):
            return default

    @staticmethod
    def _normalized_parameter_name(value: Any) -> str:
        return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")[:120]

    @staticmethod
    def _sanitize_boundary_finding(item: Any) -> Optional[dict]:
        """Retain only structural sanitizer evidence emitted by the local analyzer."""
        if not isinstance(item, dict):
            return None
        category = str(item.get("category") or "")[:80]
        if category not in _SANITIZER_BOUNDARY_CATEGORIES:
            return None
        source_kind = str(item.get("source_kind") or "")[:80]
        sink_kind = str(item.get("sink_kind") or "")[:80]
        required_context = str(item.get("required_context") or "")[:40]
        transform_kind = str(item.get("transform_kind") or "")[:80]
        protection_state = str(item.get("protection_state") or "")[:40]
        if source_kind not in _SANITIZER_SOURCE_KINDS:
            source_kind = ""
        if sink_kind not in _SANITIZER_SINK_KINDS:
            sink_kind = ""
        if required_context not in _SANITIZER_CONTEXTS:
            required_context = ""
        if transform_kind not in _SANITIZER_TRANSFORMS:
            transform_kind = ""
        if protection_state not in _SANITIZER_PROTECTION_STATES:
            protection_state = ""

        raw_source_param = str(item.get("source_param") or "")[:120]
        source_param = (
            raw_source_param
            if re.fullmatch(r"[A-Za-z0-9_.\-\[\]]{1,120}", raw_source_param)
            else ""
        )
        raw_reasons = item.get("reason_codes")
        reason_codes = list(dict.fromkeys(
            str(reason)
            for reason in raw_reasons[:20]
            if isinstance(reason, str) and str(reason) in _SANITIZER_REASON_CODES
        )) if isinstance(raw_reasons, list) else []
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        policy_method = str(details.get("policy_method") or "")[:40]
        if policy_method not in _SANITIZER_POLICY_METHODS:
            policy_method = ""
        raw_fingerprint = str(item.get("fingerprint") or "")[:64].lower()
        fingerprint = (
            raw_fingerprint
            if re.fullmatch(r"[0-9a-f]{64}", raw_fingerprint)
            else ResearchService._fingerprint(
                category, source_kind, source_param, sink_kind, transform_kind,
                item.get("source_offset"), item.get("sink_offset"),
            )
        )
        return {
            "category": category,
            "source_kind": source_kind,
            "source_param": source_param,
            "sink_kind": sink_kind,
            "required_context": required_context,
            "transform_kind": transform_kind,
            "protection_state": protection_state,
            "reason_codes": reason_codes,
            "source_offset": ResearchService._bounded_int(
                item.get("source_offset", 0), 10_000_000
            ),
            "transform_offset": ResearchService._bounded_int(
                item.get("transform_offset", 0), 10_000_000
            ),
            "sink_offset": ResearchService._bounded_int(
                item.get("sink_offset", 0), 10_000_000
            ),
            "confidence": ResearchService._bounded_float(item.get("confidence", 0.0)),
            "fingerprint": fingerprint,
            "details": {
                "hops": ResearchService._bounded_int(details.get("hops", 0), 8),
                "policy_method": policy_method or None,
                "compatible_context": (
                    details.get("compatible_context")
                    if isinstance(details.get("compatible_context"), bool)
                    else None
                ),
            },
        }

    @staticmethod
    def _boundary_contexts(param: Param, finding: dict) -> list[Optional[Context]]:
        """Resolve a static boundary to mapped contexts without guessing content."""
        contexts = sorted(list(param.contexts)[:100], key=lambda row: row.id or 0)
        sink_kind = str(finding.get("sink_kind") or "")
        sink_matches = [
            context for context in contexts
            if any(str(sink.sink_type or "") == sink_kind for sink in list(context.sinks)[:100])
        ]
        if sink_matches:
            return sink_matches[:4]

        required_context = str(finding.get("required_context") or "")
        compatible_types = {
            "HTML": {
                "HTML_TEXT", "HTML_RCDATA", "HTML_RAW_TEXT", "ATTR_QUOTED",
                "ATTR_UNQUOTED", "SRC_DOC_ATTR", "SVG_TEXT", "MATHML_TEXT",
                "FOREIGN_OBJECT", "ANNOTATION_XML",
            },
            "SCRIPT": {
                "EVENT_HANDLER_ATTR", "JS_STRING_LITERAL", "JS_TEMPLATE_LITERAL",
                "JS_IDENTIFIER", "SVG_SCRIPT",
            },
            "URL": {"URL_QUERY", "URL_FRAGMENT", "CSS_URL"},
            "CSS": {"CSS_STYLE_BLOCK", "CSS_INLINE_STYLE", "CSS_URL"},
        }.get(required_context, set())
        context_matches = [
            context for context in contexts if context.context_type in compatible_types
        ]
        return context_matches[:4] or [None]

    @staticmethod
    def _node(
        db: Session,
        experiment_id: int,
        node_type: str,
        natural_key: str,
        label: str,
        risk_score: int = 0,
        attributes: Optional[dict] = None,
    ) -> AttackSurfaceNode:
        node = db.query(AttackSurfaceNode).filter_by(
            experiment_id=experiment_id, node_type=node_type, natural_key=natural_key
        ).first()
        if node is None:
            node = AttackSurfaceNode(
                experiment_id=experiment_id,
                node_type=node_type,
                natural_key=natural_key,
                label=label[:500],
                risk_score=max(0, min(100, int(risk_score))),
                attributes=attributes or None,
            )
            db.add(node)
            db.flush()
        else:
            node.label = label[:500]
            node.risk_score = max(node.risk_score, max(0, min(100, int(risk_score))))
            if attributes:
                node.attributes = {**(node.attributes or {}), **attributes}
        return node

    @staticmethod
    def _edge(
        db: Session,
        experiment_id: int,
        source: AttackSurfaceNode,
        target: AttackSurfaceNode,
        relation: str,
        confidence: float = 1.0,
        evidence: Optional[dict] = None,
    ) -> AttackSurfaceEdge:
        edge = db.query(AttackSurfaceEdge).filter_by(
            experiment_id=experiment_id,
            source_node_id=source.id,
            target_node_id=target.id,
            relation=relation,
        ).first()
        if edge is None:
            edge = AttackSurfaceEdge(
                experiment_id=experiment_id,
                source_node_id=source.id,
                target_node_id=target.id,
                relation=relation,
                confidence=max(0.0, min(1.0, confidence)),
                evidence=evidence or None,
            )
            db.add(edge)
        return edge

    @staticmethod
    def _hypothesis(
        db: Session,
        experiment_id: int,
        hypothesis_type: str,
        title: str,
        rationale: str,
        endpoint_id: Optional[int],
        param_id: Optional[int],
        context_id: Optional[int],
        confidence: float,
        impact_score: int,
        techniques: Iterable[str],
        evidence: Optional[dict] = None,
    ) -> ResearchHypothesis:
        fingerprint = ResearchService._fingerprint(
            experiment_id, hypothesis_type, endpoint_id, param_id, context_id
        )
        priority = round(
            max(0.0, min(1.0, confidence)) * 60.0
            + max(0, min(100, impact_score)) * 0.4,
            3,
        )
        row = db.query(ResearchHypothesis).filter_by(
            experiment_id=experiment_id, fingerprint=fingerprint
        ).first()
        values = {
            "title": title[:500],
            "rationale": rationale,
            "confidence": max(0.01, min(0.99, confidence)),
            "impact_score": max(0, min(100, impact_score)),
            "priority": priority,
            "technique_candidates": list(dict.fromkeys(techniques)),
            "evidence": evidence or None,
        }
        if row is None:
            row = ResearchHypothesis(
                experiment_id=experiment_id,
                endpoint_id=endpoint_id,
                param_id=param_id,
                context_id=context_id,
                fingerprint=fingerprint,
                hypothesis_type=hypothesis_type,
                status="proposed",
                **values,
            )
            db.add(row)
        elif row.status == "proposed":
            for key, value in values.items():
                setattr(row, key, value)
        return row

    @staticmethod
    def _ingest_recon_signals(
        db: Session,
        experiment_id: int,
        target_node: AttackSurfaceNode,
        endpoints: list[Endpoint],
        recon_signals: Iterable[dict],
    ) -> dict:
        """Turn bounded passive recon observations into graph evidence and hypotheses."""
        totals = {
            "bundles": 0,
            "dom_sources": 0,
            "dom_sinks": 0,
            "navigation_sinks": 0,
            "eval_sinks": 0,
            "postmessage_listeners": 0,
            "sensitive_tokens": 0,
            "prototype_pollution": 0,
            "sanitizers": 0,
            "client_trust_findings": 0,
            "postmessage_unvalidated_sink": 0,
            "postmessage_weak_origin_validation": 0,
            "postmessage_wildcard_target": 0,
            "external_prototype_mutation": 0,
            "dom_named_property_to_sink": 0,
            "trusted_types_identity_policy": 0,
            "property_integrity_chains": 0,
            "dom_clobbering_chain": 0,
            "prototype_property_injection_chain": 0,
            "sanitizer_boundary_findings": 0,
            "sanitizer_context_mismatch": 0,
            "sanitizer_output_invalidated": 0,
            "sanitizer_partial_coverage": 0,
            "opaque_sanitizer_flow": 0,
            "trusted_types_unvalidated_flow": 0,
            "effective_sanitizer_boundary": 0,
        }
        endpoint_nodes: dict[int, AttackSurfaceNode] = {}
        endpoints_by_path: dict[str, list[Endpoint]] = {}
        targeted_boundary_groups: dict[
            tuple[int, int, Optional[int]], dict[str, Any]
        ] = {}
        targeted_boundary_records = 0
        for endpoint in endpoints:
            path = ResearchService._safe_route_path(endpoint.url_pattern)
            if not path:
                continue
            endpoints_by_path.setdefault(path, []).append(endpoint)

        for signal in list(recon_signals)[:250]:
            if not isinstance(signal, dict) or signal.get("kind") != "client_bundle":
                continue
            script_url = ResearchService._safe_artifact_url(
                str(signal.get("script_url") or "")[:2000]
            )
            if not script_url:
                continue
            route_paths = list(dict.fromkeys(filter(None, (
                ResearchService._safe_route_path(route)
                for route in list(signal.get("discovered_endpoints") or [])[:50]
            ))))
            referenced_endpoints = list(dict.fromkeys(
                endpoint
                for route_path in route_paths
                for endpoint in endpoints_by_path.get(route_path, [])
            ))[:50]
            counts = signal.get("counts") if isinstance(signal.get("counts"), dict) else {}
            normalized_counts = {
                key: ResearchService._bounded_int(counts.get(key, 0) or 0, 100_000)
                for key in totals if key != "bundles"
            }
            totals["bundles"] += 1
            for key, value in normalized_counts.items():
                totals[key] += value

            script_key = ResearchService._fingerprint(script_url)
            script_risk = min(
                100,
                normalized_counts["dom_sinks"] * 3
                + normalized_counts["eval_sinks"] * 8
                + normalized_counts["postmessage_listeners"] * 4
                + normalized_counts["prototype_pollution"] * 6
                + normalized_counts["postmessage_unvalidated_sink"] * 12
                + normalized_counts["external_prototype_mutation"] * 12
                + normalized_counts["dom_named_property_to_sink"] * 8
                + normalized_counts["trusted_types_identity_policy"] * 4
                + normalized_counts["dom_clobbering_chain"] * 16
                + normalized_counts["prototype_property_injection_chain"] * 18
                + normalized_counts["sanitizer_context_mismatch"] * 12
                + normalized_counts["sanitizer_output_invalidated"] * 14
                + normalized_counts["sanitizer_partial_coverage"] * 14
                + normalized_counts["opaque_sanitizer_flow"] * 6
                + normalized_counts["trusted_types_unvalidated_flow"] * 16,
            )
            trust_findings = []
            for item in list(signal.get("client_trust_findings") or [])[:100]:
                if not isinstance(item, dict):
                    continue
                category = str(item.get("category") or "")[:80]
                if category not in {
                    "postmessage_unvalidated_sink", "postmessage_weak_origin_validation",
                    "postmessage_wildcard_target", "external_prototype_mutation",
                    "dom_named_property_to_sink", "trusted_types_identity_policy",
                }:
                    continue
                trust_findings.append({
                    "category": category,
                    "confidence": ResearchService._bounded_float(
                        item.get("confidence", 0.0) or 0.0
                    ),
                    "severity_hint": str(item.get("severity_hint") or "")[:20],
                    "offset": ResearchService._bounded_int(
                        item.get("offset", 0) or 0, 10_000_000
                    ),
                    "code_fingerprint": str(item.get("code_fingerprint") or "")[:64],
                    "details": {
                        str(key)[:80]: str(value)[:200]
                        for key, value in (item.get("details") or {}).items()
                        if str(key) in {"event_parameter", "guard", "sink", "context", "hops", "source", "property", "variable", "policy_method"}
                    },
                })
            integrity_chains = []
            for item in list(signal.get("property_integrity_chains") or [])[:100]:
                if not isinstance(item, dict):
                    continue
                kind = str(item.get("kind") or "")[:80]
                if kind not in {"dom_clobbering_chain", "prototype_property_injection_chain"}:
                    continue
                metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
                safe_metadata = {
                    str(key)[:80]: value
                    for key, value in metadata.items()
                    if str(key) in {
                        "named_property", "base", "relationship", "definition_fingerprints",
                        "definition_lines", "read_line", "sink_kind", "trust", "source_kind",
                        "source_symbol", "mutation_operation", "mutation_target", "mutation_line",
                        "injection_mode", "gadget_property", "gadget_line",
                    }
                    and isinstance(value, (str, int, float, bool, list, type(None)))
                }
                integrity_chains.append({
                    "kind": kind,
                    "fingerprint": str(item.get("fingerprint") or "")[:64],
                    "confidence": ResearchService._bounded_float(
                        item.get("confidence", 0.0) or 0.0
                    ),
                    "metadata": safe_metadata,
                })
            boundary_findings = []
            for item in list(signal.get("sanitizer_boundary_findings") or [])[:100]:
                finding = ResearchService._sanitize_boundary_finding(item)
                if finding is not None:
                    boundary_findings.append(finding)
            script_node = ResearchService._node(
                db,
                experiment_id,
                "client_script",
                script_key,
                script_url,
                script_risk,
                {
                    "size_bytes": ResearchService._bounded_int(
                        signal.get("size_bytes", 0) or 0, 1_000_000_000
                    ),
                    "counts": normalized_counts,
                    "client_trust_findings": trust_findings,
                    "property_integrity_chains": integrity_chains,
                    "sanitizer_boundary_findings": boundary_findings,
                },
            )
            ResearchService._edge(db, experiment_id, target_node, script_node, "loads", 1.0)
            for chain in integrity_chains:
                fingerprint = chain["fingerprint"] or ResearchService._fingerprint(
                    f"{script_key}:{chain['kind']}:{chain['metadata']}"
                )
                chain_node = ResearchService._node(
                    db,
                    experiment_id,
                    chain["kind"],
                    fingerprint,
                    chain["kind"].replace("_", " ").title(),
                    88 if chain["kind"] == "prototype_property_injection_chain" else 82,
                    {"fingerprint": fingerprint, "confidence": chain["confidence"], **chain["metadata"]},
                )
                ResearchService._edge(
                    db,
                    experiment_id,
                    script_node,
                    chain_node,
                    "supports",
                    chain["confidence"],
                    {"evidence_type": "ordered_property_integrity_chain"},
                )

            source_node = None
            if normalized_counts["dom_sources"]:
                source_node = ResearchService._node(
                    db, experiment_id, "client_source", f"{script_key}:source",
                    "Browser-controlled DOM sources", 55,
                    {"count": normalized_counts["dom_sources"]},
                )
                ResearchService._edge(db, experiment_id, script_node, source_node, "contains", 0.9)

            sink_groups = {
                "dom_sink": normalized_counts["dom_sinks"],
                "navigation_sink": normalized_counts["navigation_sinks"],
                "code_execution_sink": normalized_counts["eval_sinks"],
            }
            for sink_type, count in sink_groups.items():
                if not count:
                    continue
                sink_node = ResearchService._node(
                    db, experiment_id, sink_type, f"{script_key}:{sink_type}",
                    sink_type.replace("_", " ").title(), 85 if sink_type == "code_execution_sink" else 70,
                    {"count": count},
                )
                ResearchService._edge(db, experiment_id, script_node, sink_node, "contains", 0.9)
                if source_node is not None:
                    ResearchService._edge(
                        db, experiment_id, source_node, sink_node, "co_occurs_with", 0.35,
                        {"interpretation": "static proximity signal; dynamic taint confirmation required"},
                    )

            for route_path in route_paths:
                for endpoint in endpoints_by_path.get(route_path, []):
                    endpoint_node = endpoint_nodes.get(endpoint.id)
                    if endpoint_node is None:
                        endpoint_node = ResearchService._node(
                            db, experiment_id, "endpoint", str(endpoint.id),
                            f"{endpoint.method.upper()} {endpoint.url_pattern}",
                            ImpactScorer.score_attack_surface(endpoint)["score"],
                        )
                        endpoint_nodes[endpoint.id] = endpoint_node
                    ResearchService._edge(
                        db, experiment_id, script_node, endpoint_node, "references", 0.8,
                        {"route": route_path},
                    )

            candidate_endpoints = referenced_endpoints if route_paths else endpoints[:50]
            for finding in boundary_findings:
                if (
                    targeted_boundary_records >= 250
                    or finding["category"] not in _RISKY_SANITIZER_BOUNDARY_CATEGORIES
                ):
                    continue
                source_name = ResearchService._normalized_parameter_name(
                    finding.get("source_param")
                )
                if not source_name:
                    continue
                for endpoint in candidate_endpoints:
                    matching_params = [
                        param for param in list(endpoint.params)[:100]
                        if param.is_controllable
                        and ResearchService._normalized_parameter_name(param.name) == source_name
                    ]
                    for param in matching_params[:4]:
                        for context in ResearchService._boundary_contexts(param, finding):
                            key = (endpoint.id, param.id, context.id if context else None)
                            if key not in targeted_boundary_groups:
                                if len(targeted_boundary_groups) >= 100:
                                    break
                                targeted_boundary_groups[key] = {
                                    "endpoint": endpoint,
                                    "param": param,
                                    "context": context,
                                    "findings": [],
                                }
                            group = targeted_boundary_groups.get(key)
                            if group is None or len(group["findings"]) >= 12:
                                continue
                            record = {
                                **finding,
                                "script_fingerprint": script_key,
                            }
                            record_key = (
                                record["fingerprint"], record["script_fingerprint"]
                            )
                            if any(
                                (item["fingerprint"], item["script_fingerprint"])
                                == record_key
                                for item in group["findings"]
                            ):
                                continue
                            group["findings"].append(record)
                            targeted_boundary_records += 1
                            if targeted_boundary_records >= 250:
                                break
                        if targeted_boundary_records >= 250:
                            break
                    if targeted_boundary_records >= 250:
                        break

        for group_key in sorted(targeted_boundary_groups)[:100]:
            group = targeted_boundary_groups[group_key]
            endpoint = group["endpoint"]
            param = group["param"]
            context = group["context"]
            findings = list(group["findings"])[:12]
            if not findings:
                continue
            categories = sorted({item["category"] for item in findings})
            sink_kinds = sorted({item["sink_kind"] for item in findings if item["sink_kind"]})
            confidence = max(0.45, max(item["confidence"] for item in findings))
            impact = ImpactScorer.score_attack_surface(endpoint, param, context)["score"]
            ResearchService._hypothesis(
                db,
                experiment_id,
                "sanitizer_boundary",
                f"Sanitizer boundary on {param.name} into {', '.join(sink_kinds) or 'a browser sink'}",
                "Ordered analysis connected this controllable parameter to a transform and consuming browser context. Use an inert marker to compare the value before and after the transform, then require execution-oracle evidence before confirmation.",
                endpoint.id,
                param.id,
                context.id if context else None,
                confidence,
                min(100, 45 + impact),
                [
                    "sanitizer-boundary-differential", "context-compatibility",
                    "post-transform-taint", "runtime-reachability",
                ],
                {
                    "evidence_type": "ordered_sanitizer_boundary_analysis",
                    "targeted": True,
                    "endpoint_path": ResearchService._safe_route_path(endpoint.url_pattern),
                    "parameter_name": str(param.name or "")[:255],
                    "parameter_location": str(param.location or "")[:20],
                    "context_type": str(context.context_type)[:50] if context else None,
                    "categories": categories[:6],
                    "sink_kinds": sink_kinds[:12],
                    "finding_count": len(findings),
                    "ordered_boundaries": findings,
                },
            )

        executable_sinks = totals["dom_sinks"] + totals["eval_sinks"]
        if totals["dom_sources"] and executable_sinks:
            ResearchService._hypothesis(
                db, experiment_id, "client_side_taint",
                "Client-side source-to-sink paths require dynamic taint confirmation",
                "Static analysis found browser-controlled sources and executable sinks in the same client bundles. This is a lead, not proof; prioritize instrumented source-to-sink confirmation and sanitizer-boundary differentials.",
                None, None, None, 0.46, min(100, 45 + executable_sinks),
                ["dynamic-taint-confirmation", "source-substitution", "sanitizer-boundary", "parser-differential"],
                {"signal_totals": totals, "static_relation_confidence": 0.35},
            )
        postmessage_risk = (
            totals["postmessage_unvalidated_sink"]
            + totals["postmessage_weak_origin_validation"]
            + totals["postmessage_wildcard_target"]
        )
        if totals["postmessage_listeners"]:
            ResearchService._hypothesis(
                db, experiment_id, "postmessage_boundary",
                "Cross-origin postMessage trust boundary",
                "Client bundles register message handlers. Verify origin/source validation and trace message-controlled data into navigation or DOM sinks with harmless canaries.",
                None, None, None,
                0.72 if totals["postmessage_unvalidated_sink"] else 0.52,
                min(100, 45 + totals["postmessage_listeners"] * 3 + postmessage_risk * 8),
                ["origin-validation", "source-validation", "message-shape-differential", "dynamic-taint-confirmation"],
                {
                    "listener_count": totals["postmessage_listeners"],
                    "unvalidated_sink_count": totals["postmessage_unvalidated_sink"],
                    "weak_origin_check_count": totals["postmessage_weak_origin_validation"],
                    "wildcard_target_count": totals["postmessage_wildcard_target"],
                    "evidence_type": "passive_client_trust_analysis",
                },
            )
        if (
            totals["prototype_pollution"]
            or totals["external_prototype_mutation"]
            or totals["prototype_property_injection_chain"]
        ):
            ResearchService._hypothesis(
                db, experiment_id, "prototype_pollution",
                "Prototype mutation primitives in client code",
                "Static primitives may expose a property-injection path. Use non-destructive marker properties and require an observable gadget effect before promotion.",
                None, None, None,
                0.91 if totals["prototype_property_injection_chain"] else 0.74 if totals["external_prototype_mutation"] else 0.34,
                min(
                    100,
                    40
                    + totals["prototype_pollution"] * 4
                    + totals["external_prototype_mutation"] * 12
                    + totals["prototype_property_injection_chain"] * 18,
                ),
                ["marker-property", "merge-path-differential", "gadget-confirmation"],
                {
                    "primitive_count": totals["prototype_pollution"],
                    "external_mutation_flow_count": totals["external_prototype_mutation"],
                    "ordered_gadget_chain_count": totals["prototype_property_injection_chain"],
                    "evidence_type": "passive_client_trust_analysis",
                },
            )
        if totals["dom_named_property_to_sink"] or totals["dom_clobbering_chain"]:
            ResearchService._hypothesis(
                db, experiment_id, "dom_clobbering",
                "Named DOM property reaches a sensitive browser sink",
                "Static analysis linked implicit window/document named access with a sensitive sink. Confirm element-name control and type confusion with an inert marker before promotion.",
                None, None, None, 0.91 if totals["dom_clobbering_chain"] else 0.66,
                min(
                    100,
                    48
                    + totals["dom_named_property_to_sink"] * 9
                    + totals["dom_clobbering_chain"] * 16,
                ),
                ["named-property-inventory", "type-validation", "harmless-marker-confirmation"],
                {
                    "named_property_flow_count": totals["dom_named_property_to_sink"],
                    "html_correlated_chain_count": totals["dom_clobbering_chain"],
                    "evidence_type": "passive_client_trust_analysis",
                },
            )
        risky_sanitizer_boundaries = (
            totals["sanitizer_context_mismatch"]
            + totals["sanitizer_output_invalidated"]
            + totals["sanitizer_partial_coverage"]
            + totals["opaque_sanitizer_flow"]
            + totals["trusted_types_unvalidated_flow"]
        )
        if risky_sanitizer_boundaries:
            ResearchService._hypothesis(
                db, experiment_id, "sanitizer_boundary",
                "Sanitizer boundary does not fully protect the consuming context",
                "Ordered operand-level analysis found a partial, invalidated, opaque, or context-mismatched transform on an external-data path. Confirm the exact boundary with inert parser differentials before promotion.",
                None, None, None,
                0.86 if (
                    totals["sanitizer_partial_coverage"]
                    or totals["sanitizer_output_invalidated"]
                    or totals["trusted_types_unvalidated_flow"]
                ) else 0.68,
                min(100, 52 + risky_sanitizer_boundaries * 10),
                [
                    "sanitizer-boundary-differential", "context-compatibility",
                    "post-transform-taint", "runtime-reachability",
                ],
                {
                    "context_mismatch_count": totals["sanitizer_context_mismatch"],
                    "invalidated_output_count": totals["sanitizer_output_invalidated"],
                    "partial_coverage_count": totals["sanitizer_partial_coverage"],
                    "opaque_transform_count": totals["opaque_sanitizer_flow"],
                    "trusted_types_unvalidated_flow_count": totals["trusted_types_unvalidated_flow"],
                    "effective_boundary_count": totals["effective_sanitizer_boundary"],
                    "evidence_type": "ordered_sanitizer_boundary_analysis",
                },
            )
        if totals["trusted_types_identity_policy"] or totals["trusted_types_unvalidated_flow"]:
            ResearchService._hypothesis(
                db, experiment_id, "trusted_types_policy",
                "Trusted Types policy may pass external strings through unchanged",
                "A policy method appears to return its argument without validation. Confirm which call sites can supply external data and whether enforcement covers the associated sink.",
                None, None, None,
                0.9 if totals["trusted_types_unvalidated_flow"] else 0.48,
                min(
                    100,
                    45
                    + totals["trusted_types_identity_policy"] * 4
                    + totals["trusted_types_unvalidated_flow"] * 16,
                ),
                ["policy-callsite-correlation", "enforcement-observation", "safe-string-differential"],
                {
                    "identity_policy_method_count": totals["trusted_types_identity_policy"],
                    "complete_unvalidated_flow_count": totals["trusted_types_unvalidated_flow"],
                    "evidence_type": "passive_client_trust_analysis",
                },
            )
        if totals["sensitive_tokens"]:
            ResearchService._hypothesis(
                db, experiment_id, "client_secret_exposure",
                "Potential credential material embedded in client bundles",
                "Secret-like values were fingerprinted without retaining their raw content. Confirm whether they are public identifiers or privileged credentials using metadata-only, non-mutating checks.",
                None, None, None, 0.42, min(100, 55 + totals["sensitive_tokens"] * 3),
                ["metadata-classification", "scope-validation", "rotation-check"],
                {"fingerprinted_indicator_count": totals["sensitive_tokens"]},
            )
        return totals

    @staticmethod
    def plan_experiment(
        db: Session,
        experiment_id: int,
        recon_signals: Optional[Iterable[dict]] = None,
    ) -> dict:
        """Build a graph and ranked, evidence-backed hypotheses for one run."""
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if experiment is None:
            raise ValueError(f"Experiment {experiment_id} not found")
        endpoint_ids = RunStateService.endpoint_ids(db, experiment_id)
        endpoints = (
            db.query(Endpoint).filter(Endpoint.id.in_(endpoint_ids)).all()
            if endpoint_ids else []
        )
        target_node = ResearchService._node(
            db, experiment_id, "target", str(experiment.target_id),
            experiment.target.base_url, 20,
            {"allowed_hosts": (experiment.target.scope_tags or {}).get("allowed_hosts", [])},
        )

        for endpoint in endpoints:
            endpoint_risk = ImpactScorer.score_attack_surface(endpoint)["score"]
            endpoint_node = ResearchService._node(
                db, experiment_id, "endpoint", str(endpoint.id),
                f"{endpoint.method.upper()} {endpoint.url_pattern}", endpoint_risk,
                {"method": endpoint.method.upper(), "path": urlparse(endpoint.url_pattern).path},
            )
            ResearchService._edge(db, experiment_id, target_node, endpoint_node, "exposes")
            ResearchService._hypothesis(
                db, experiment_id, "cors",
                f"Cross-origin trust boundary on {endpoint.method.upper()} endpoint",
                "Verify whether origin reflection, null-origin trust, or credentials create an unintended cross-origin read boundary.",
                endpoint.id, None, None, 0.22, min(100, 25 + endpoint_risk),
                ["origin-reflection", "null-origin", "credentialed-origin", "preflight-differential"],
                {"method": endpoint.method.upper()},
            )
            path_lower = urlparse(endpoint.url_pattern).path.lower()
            if "graphql" in path_lower:
                ResearchService._hypothesis(
                    db, experiment_id, "graphql",
                    f"Schema-driven GraphQL research on {path_lower}",
                    "GraphQL surface detected; prioritize schema-derived operations, authorization boundaries, alias/depth budgets, and input coercion differentials.",
                    endpoint.id, None, None, 0.72, min(100, 50 + endpoint_risk),
                    ["schema-introspection", "operation-enumeration", "authorization-differential", "bounded-depth", "input-coercion"],
                    {"path": path_lower},
                )
            if endpoint.custom_steps:
                ResearchService._hypothesis(
                    db, experiment_id, "stateful_workflow",
                    f"Stateful workflow boundary on {path_lower or '/'}",
                    "Captured navigation or request steps indicate state-dependent behavior; preserve prerequisites and compare transitions rather than testing requests in isolation.",
                    endpoint.id, None, None, 0.68, min(100, 45 + endpoint_risk),
                    ["state-replay", "step-omission", "order-differential", "role-boundary"],
                    {"step_count": len(endpoint.custom_steps) if isinstance(endpoint.custom_steps, list) else 1},
                )

            for param in endpoint.params:
                attack_score = ImpactScorer.score_attack_surface(endpoint, param)["score"]
                param_node = ResearchService._node(
                    db, experiment_id, "parameter", str(param.id),
                    f"{param.location}:{param.name}", attack_score,
                    {"location": param.location, "sample_present": param.sample_value is not None},
                )
                ResearchService._edge(db, experiment_id, endpoint_node, param_node, "accepts")
                normalized_name = re.sub(r"[^a-z0-9]+", "_", (param.name or "").lower()).strip("_")
                terms = set(filter(None, normalized_name.split("_"))) | {normalized_name}
                for hypothesis_type, rule in _SEMANTIC_HYPOTHESES.items():
                    matched = sorted(terms & rule["terms"])
                    if not matched:
                        continue
                    ResearchService._hypothesis(
                        db, experiment_id, hypothesis_type,
                        f"{hypothesis_type.replace('_', ' ').title()} candidate in {param.name}",
                        f"Parameter semantics ({', '.join(matched)}) suggest {hypothesis_type.replace('_', ' ')} behavior; verify with bounded differential canaries.",
                        endpoint.id, param.id, None,
                        rule["confidence"], min(100, 30 + attack_score), rule["techniques"],
                        {"matched_terms": matched, "parameter_location": param.location},
                    )

                for context in [value for value in endpoint.contexts if value.param_id == param.id]:
                    context_risk = ImpactScorer.score_attack_surface(endpoint, param, context)["score"]
                    context_node = ResearchService._node(
                        db, experiment_id, "context", str(context.id), context.context_type,
                        min(100, 35 + context_risk),
                        {"tag": context.tag, "attribute": context.attribute, "script_path": context.script_path},
                    )
                    ResearchService._edge(
                        db, experiment_id, param_node, context_node, "reflects_into", 0.85,
                        {"snippet_present": bool(context.snippet)},
                    )
                    techniques = list(_CONTEXT_TECHNIQUES.get(context.context_type, ["context-differential"]))
                    sinks = list(context.sinks)
                    if sinks:
                        techniques = ["dom-source-to-sink", "taint-confirmation", *techniques]
                    ResearchService._hypothesis(
                        db, experiment_id, "dom_xss" if sinks else "reflected_xss",
                        f"Executable input path via {param.name} into {context.context_type}",
                        (
                            f"Input is observed in {context.context_type}"
                            + (f" and reaches {len(sinks)} mapped browser sink(s)" if sinks else "")
                            + "; test parser-accurate, context-specific execution hypotheses."
                        ),
                        endpoint.id, param.id, context.id,
                        0.78 if sinks else 0.58,
                        min(100, 45 + context_risk + (15 if sinks else 0)),
                        techniques,
                        {"context_type": context.context_type, "sink_count": len(sinks)},
                    )
                    for sink in sinks:
                        sink_node = ResearchService._node(
                            db, experiment_id, "sink", str(sink.id), sink.sink_type, 85,
                            {
                                "detected_via": (
                                    sink.detected_via.value
                                    if hasattr(sink.detected_via, "value")
                                    else str(sink.detected_via)
                                ),
                                "js_location": sink.js_location,
                            },
                        )
                        ResearchService._edge(
                            db, experiment_id, context_node, sink_node, "flows_to", 0.9,
                            {"taint_path": sink.taint_path or []},
                        )
        signal_summary = ResearchService._ingest_recon_signals(
            db, experiment_id, target_node, endpoints, recon_signals or []
        )
        db.commit()

        hypotheses = db.query(ResearchHypothesis).filter_by(experiment_id=experiment_id).order_by(
            ResearchHypothesis.priority.desc(), ResearchHypothesis.id
        ).all()
        limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
        brain_memory = dict(limits.get("campaign_brain") or {})
        if (
            settings.LLM_ENABLED
            and settings.LLM_CAMPAIGN_ADVISOR
            and not os.getenv("PYTEST_CURRENT_TEST")
            and not brain_memory.get("llm_advice")
            and hypotheses
        ):
            try:
                from backend_api.services.llm_service import LLMService

                advisor_inputs = []
                tenant_id = experiment.target.tenant_id
                for row in hypotheses[:12]:
                    candidates = list(row.technique_candidates or [])
                    stats = db.query(ResearchTechniqueStat).filter(
                        ResearchTechniqueStat.tenant_id == tenant_id,
                        ResearchTechniqueStat.technique.in_(candidates),
                    ).all() if candidates else []
                    history_by_technique: dict[str, dict[str, float]] = {}
                    for stat in stats:
                        totals = history_by_technique.setdefault(
                            stat.technique,
                            {"uses": 0, "hits": 0, "reward_sum": 0.0},
                        )
                        totals["uses"] += int(stat.successes or 0) + int(stat.failures or 0)
                        totals["hits"] += int(stat.successes or 0)
                        totals["reward_sum"] += float(stat.reward_sum or 0.0)
                    advisor_inputs.append({
                        "id": row.id,
                        "type": row.hypothesis_type,
                        "confidence": row.confidence,
                        "impact": row.impact_score,
                        "techniques": candidates,
                        "evidence": row.evidence or {},
                        "technique_history": [
                            {
                                "technique": technique,
                                "uses": int(totals["uses"]),
                                "hits": int(totals["hits"]),
                                "mean_reward": (
                                    float(totals["reward_sum"])
                                    / max(1, int(totals["uses"]))
                                ),
                            }
                            for technique, totals in history_by_technique.items()
                        ],
                    })
                advice = LLMService.advise_hypotheses(advisor_inputs)
                by_id = {row.id: row for row in hypotheses}
                for recommendation in advice.get("recommendations", []):
                    row = by_id.get(recommendation.get("id"))
                    if row is None:
                        continue
                    row.priority = round(
                        float(row.priority or 0.0)
                        + int(recommendation.get("priority_adjustment") or 0),
                        3,
                    )
                    technique = recommendation.get("technique")
                    candidates = list(row.technique_candidates or [])
                    if technique in candidates:
                        row.technique_candidates = [
                            technique, *[candidate for candidate in candidates if candidate != technique]
                        ]
                    evidence = dict(row.evidence or {})
                    evidence["llm_advice"] = {
                        "model": settings.LLM_MODEL,
                        "priority_adjustment": int(recommendation.get("priority_adjustment") or 0),
                        "technique": technique,
                        "rationale": str(recommendation.get("rationale") or "")[:300],
                    }
                    row.evidence = evidence
                brain_memory["llm_advice"] = {
                    "model": settings.LLM_MODEL,
                    "provider": "local" if settings.LLM_PREFER_LOCAL else "configured-order",
                    **advice,
                }
                limits["campaign_brain"] = brain_memory
                experiment.limits = limits
                db.commit()
                hypotheses = db.query(ResearchHypothesis).filter_by(
                    experiment_id=experiment_id
                ).order_by(ResearchHypothesis.priority.desc(), ResearchHypothesis.id).all()
            except Exception as advisor_error:
                logger.warning("Local campaign advisor failed; deterministic plan retained: %s", advisor_error)
        summary = {
            "surface_nodes": db.query(AttackSurfaceNode).filter_by(experiment_id=experiment_id).count(),
            "surface_edges": db.query(AttackSurfaceEdge).filter_by(experiment_id=experiment_id).count(),
            "hypotheses": len(hypotheses),
            "recon_signals": signal_summary,
            "top_hypotheses": [
                {
                    "id": row.id,
                    "type": row.hypothesis_type,
                    "title": row.title,
                    "priority": row.priority,
                    "confidence": row.confidence,
                }
                for row in hypotheses[:10]
            ],
        }
        limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
        limits["research"] = summary
        experiment.limits = limits
        db.commit()
        return summary

    @staticmethod
    def hypothesis_for_context(
        db: Session,
        experiment_id: int,
        endpoint_id: int,
        param_id: int,
        context_id: Optional[int],
    ) -> Optional[ResearchHypothesis]:
        query = db.query(ResearchHypothesis).filter(
            ResearchHypothesis.experiment_id == experiment_id,
            ResearchHypothesis.endpoint_id == endpoint_id,
            ResearchHypothesis.param_id == param_id,
        )
        if context_id is not None:
            contextual = query.filter(ResearchHypothesis.context_id == context_id).order_by(
                ResearchHypothesis.priority.desc()
            ).first()
            if contextual:
                return contextual
        return query.order_by(ResearchHypothesis.priority.desc()).first()

    @staticmethod
    def context_fingerprint(hypothesis: ResearchHypothesis, context: Optional[Context], profile: Optional[dict]) -> str:
        profile = profile or {}
        return ":".join([
            hypothesis.hypothesis_type,
            context.context_type if context else "none",
            "waf" if profile.get("waf_detected") else "no-waf",
            "csp" if profile.get("csp_rules") else "no-csp",
        ])[:180]

    @staticmethod
    def select_technique(
        db: Session,
        hypothesis: ResearchHypothesis,
        context: Optional[Context],
        filter_profile: Optional[dict],
    ) -> str:
        candidates = list(hypothesis.technique_candidates or ["context-differential"])
        fingerprint = ResearchService.context_fingerprint(hypothesis, context, filter_profile)
        tenant_id = hypothesis.experiment.target.tenant_id
        stats = {
            row.technique: row
            for row in db.query(ResearchTechniqueStat).filter(
                ResearchTechniqueStat.tenant_id == tenant_id,
                ResearchTechniqueStat.context_fingerprint == fingerprint,
                ResearchTechniqueStat.technique.in_(candidates),
            ).all()
        }
        total_uses = sum(row.successes + row.failures for row in stats.values())
        ranked = []
        for index, technique in enumerate(candidates):
            row = stats.get(technique)
            uses = (row.successes + row.failures) if row else 0
            mean = ((row.successes if row else 0) + 1.0) / (uses + 2.0)
            exploration = math.sqrt(2.0 * math.log(total_uses + 2.0) / (uses + 1.0))
            ranked.append((mean + 0.35 * exploration, -index, technique))
        return max(ranked)[2]

    @staticmethod
    def recommended_strategy(
        hypothesis: Optional[ResearchHypothesis],
        context: Context,
        filter_profile: Optional[dict],
        fallback: Strategy,
    ) -> Strategy:
        profile = filter_profile or {}
        if profile.get("waf_detected") or profile.get("blocked_tokens"):
            return Strategy.UNICODE_HUNT
        csp = profile.get("csp_rules") or {}
        if csp and not csp.get("allow_inline_scripts", True):
            return Strategy.CSP_AWARE
        if context.context_type in {"JS_STRING_LITERAL", "JS_IDENTIFIER", "EVENT_HANDLER_ATTR", "JSON_VALUE"}:
            return Strategy.JS_STRING_SPECIALIST
        if hypothesis and hypothesis.hypothesis_type in {"dom_xss", "reflected_xss"}:
            return Strategy.SMART_ADAPTIVE
        return fallback

    @staticmethod
    def classify_payload(payload: str, fallback: str = "context-differential") -> str:
        lowered = payload.lower()
        if "__proto__" in lowered or "constructor[prototype]" in lowered or "constructor.prototype" in lowered:
            return "prototype-pollution"
        if re.search(r"<(?:form|a|iframe)[^>]+(?:id|name)=", lowered):
            return "dom-clobbering"
        if "postmessage" in lowered:
            return "postMessage"
        if "javascript:" in lowered:
            return "javascript-uri"
        if "&#" in lowered or "%" in lowered or "\\u" in lowered:
            return "encoding-differential"
        if "<svg" in lowered:
            return "svg-event"
        if re.search(r"\bon[a-z]+\s*=", lowered):
            return "event-handler"
        if "<script" in lowered:
            return "script-element"
        return fallback

    @staticmethod
    def rank_payloads(
        db: Session,
        hypothesis: Optional[ResearchHypothesis],
        context: Optional[Context],
        filter_profile: Optional[dict],
        payloads: Iterable[str],
    ) -> list[str]:
        """Order payloads using learned outcomes while preserving family diversity.

        The older planner chose a technique label but never used it to order the
        concrete payloads. This method closes that action gap: each payload is
        classified by the primitive it actually exercises, scored with the
        cross-run posterior for this context, and round-robined by family.
        """
        rows = list(payloads)
        if not rows or hypothesis is None:
            return rows
        fingerprint = ResearchService.context_fingerprint(hypothesis, context, filter_profile)
        tenant_id = hypothesis.experiment.target.tenant_id
        families: dict[str, list[tuple[int, str]]] = {}
        for index, payload in enumerate(rows):
            technique = ResearchService.classify_payload(payload)
            families.setdefault(technique, []).append((index, payload))

        stats = {
            stat.technique: stat
            for stat in db.query(ResearchTechniqueStat).filter(
                ResearchTechniqueStat.tenant_id == tenant_id,
                ResearchTechniqueStat.context_fingerprint == fingerprint,
                ResearchTechniqueStat.technique.in_(list(families)),
            ).all()
        }
        total_uses = sum(
            int(stat.successes or 0) + int(stat.failures or 0)
            for stat in stats.values()
        )

        def family_value(technique: str) -> tuple[float, str]:
            stat = stats.get(technique)
            uses = int(stat.successes or 0) + int(stat.failures or 0) if stat else 0
            mean = (float(stat.successes or 0) + 1.0) / (uses + 2.0) if stat else 0.5
            exploration = math.sqrt(2.0 * math.log(total_uses + 2.0) / (uses + 1.0))
            return mean + 0.30 * exploration, technique

        family_order = sorted(families, key=family_value, reverse=True)
        ordered: list[str] = []
        depth = 0
        while len(ordered) < len(rows):
            added = False
            for technique in family_order:
                family = families[technique]
                if depth < len(family):
                    ordered.append(family[depth][1])
                    added = True
            if not added:
                break
            depth += 1
        return ordered

    @staticmethod
    def attach_test_case(
        db: Session,
        test_case: TestCase,
        hypothesis: Optional[ResearchHypothesis],
        selected_technique: Optional[str] = None,
        context_fingerprint: Optional[str] = None,
    ) -> None:
        if hypothesis is None:
            return
        technique = ResearchService.classify_payload(
            test_case.payload, selected_technique or "context-differential"
        )
        test_case.research_hypothesis_id = hypothesis.id
        test_case.technique = technique
        test_case.research_metadata = {
            "hypothesis_type": hypothesis.hypothesis_type,
            "planner_priority": hypothesis.priority,
            "planner_technique_intent": selected_technique,
            "selected_technique": technique,
            "context_fingerprint": context_fingerprint,
            "llm_advice": (hypothesis.evidence or {}).get("llm_advice"),
        }
        if hypothesis.status == "proposed":
            hypothesis.status = "scheduled"

    @staticmethod
    def learn_from_execution(db: Session, execution: Execution, result: Optional[dict] = None) -> Optional[dict]:
        test_case = execution.test_case
        hypothesis = test_case.research_hypothesis
        if hypothesis is None:
            return None
        existing = db.query(ResearchObservation).filter_by(
            hypothesis_id=hypothesis.id, execution_id=execution.id
        ).first()
        if existing:
            return {"hypothesis_id": hypothesis.id, "status": hypothesis.status, "deduplicated": True}

        result = result or {}
        hit = execution.oracle_status == OracleStatus.HIT
        raw_logs = result.get("logs")
        if not isinstance(raw_logs, Mapping):
            raw_logs = parse_execution_logs(execution.logs)
        logs = sanitize_execution_logs(
            raw_logs,
            test_case_id=execution.test_case_id,
            attempt_no=execution.attempt_no,
        )
        sink_signal = bool(logs.get("sink") or logs.get("sinks") or logs.get("auditor_vuln"))

        coverage = (
            logs.get("runtime_code_coverage")
            if isinstance(logs.get("runtime_code_coverage"), dict)
            else {}
        )
        coverage_findings = coverage.get("findings") if isinstance(coverage.get("findings"), list) else []
        activation_categories = {
            str(item.get("category") or "")
            for item in coverage_findings[:250]
            if isinstance(item, dict) and item.get("runtime_reached") is True
        }
        relevant_activation_categories = {
            "client_side_taint": {"dom_sink", "code_execution_sink", "navigation_sink"},
            "dom_xss": {"dom_sink", "code_execution_sink"},
            "reflected_xss": {"dom_sink", "code_execution_sink", "navigation_sink"},
            "stored_xss": {"dom_sink", "code_execution_sink"},
            "postmessage_boundary": {
                "postmessage_unvalidated_sink",
                "postmessage_weak_origin_validation",
                "postmessage_wildcard_target",
            },
            "dom_clobbering": {"dom_named_property_to_sink", "dom_sink", "navigation_sink"},
            "trusted_types_policy": {"trusted_types_identity_policy", "dom_sink", "code_execution_sink"},
            "prototype_pollution": {"external_prototype_mutation", "dom_sink", "code_execution_sink"},
            "sanitizer_boundary": {
                "dom_sink", "code_execution_sink", "navigation_sink",
            },
        }.get(hypothesis.hypothesis_type, set())
        activation_matches = sorted(
            activation_categories & relevant_activation_categories
        )
        runtime_activation_signal = bool(coverage.get("available") and activation_matches)

        differential = (
            logs.get("dom_marker_differential")
            if isinstance(logs.get("dom_marker_differential"), dict)
            else {}
        )
        differential_summary = (
            differential.get("summary")
            if isinstance(differential.get("summary"), dict)
            else {}
        )
        materialized_count = ResearchService._bounded_int(
            differential_summary.get("new_marker_sites")
            if differential.get("differential_available")
            else differential_summary.get("materialized_sites"),
            250,
        )
        materialization_types = {
            "client_side_taint", "dom_xss", "reflected_xss", "stored_xss",
            "postmessage_boundary", "dom_clobbering", "trusted_types_policy",
            "sanitizer_boundary",
        }
        marker_materialization_signal = bool(
            differential.get("available")
            and materialized_count > 0
            and hypothesis.hypothesis_type in materialization_types
        )
        lineage = normalize_runtime_lineage_evidence(
            logs.get("runtime_lineage")
            if isinstance(logs.get("runtime_lineage"), dict)
            else logs.get("runtime_causal_lineage"),
            test_case_id=execution.test_case_id,
            attempt_no=execution.attempt_no,
        )
        lineage_summary = lineage.get("summary", {}) if lineage else {}
        lineage_causal_count = ResearchService._bounded_int(
            lineage_summary.get("causal_only"), 250
        )
        lineage_value_count = ResearchService._bounded_int(
            lineage_summary.get("value_influence"), 250
        )
        lineage_classification = (
            "value_influence"
            if lineage_value_count > 0
            else "causal_only" if lineage_causal_count > 0 else None
        )
        lineage_value_signal = lineage_classification == "value_influence"
        lineage_causal_signal = lineage_classification == "causal_only"
        evidence_signal = bool(
            sink_signal
            or runtime_activation_signal
            or marker_materialization_signal
            or lineage_classification
        )
        if hit:
            signal_type = "browser_execution"
            outcome = "supported"
            strength = 1.0
        else:
            if sink_signal and (
                runtime_activation_signal
                or marker_materialization_signal
                or lineage_value_signal
            ):
                signal_type = "multi_source_runtime_signal"
                strength = 0.55
            elif lineage_value_signal and (
                runtime_activation_signal or marker_materialization_signal
            ):
                signal_type = "runtime_value_influence_correlation"
                strength = 0.52
            elif runtime_activation_signal and marker_materialization_signal:
                signal_type = "runtime_marker_correlation"
                strength = 0.5
            elif lineage_value_signal:
                signal_type = "runtime_value_influence"
                strength = 0.46
            elif sink_signal:
                signal_type = "sink_telemetry"
                strength = 0.35
            elif marker_materialization_signal:
                signal_type = "marker_materialized"
                strength = 0.32
            elif runtime_activation_signal:
                signal_type = "runtime_reached"
                strength = 0.28
            elif lineage_causal_signal:
                signal_type = "runtime_causal_only"
                strength = 0.18
            else:
                signal_type = "negative_probe"
                strength = 0.0
            outcome = "signal" if evidence_signal else "inconclusive"
        observation = ResearchObservation(
            hypothesis_id=hypothesis.id,
            execution_id=execution.id,
            signal_type=signal_type,
            outcome=outcome,
            strength=strength,
            details={
                "oracle_status": execution.oracle_status.value,
                "technique": test_case.technique,
                "duration_ms": execution.duration_ms,
                "status_code": result.get("status_code"),
                "runtime_coverage_available": bool(coverage.get("available")),
                "runtime_activation_categories": activation_matches[:20],
                "dom_differential_available": bool(
                    differential.get("differential_available")
                ),
                "marker_materialized_sites": materialized_count,
                "runtime_lineage_available": lineage is not None,
                "runtime_lineage_classification": lineage_classification,
                "runtime_lineage_candidates": ResearchService._bounded_int(
                    lineage_summary.get("candidates"), 250
                ),
                "runtime_lineage_causal_only": lineage_causal_count,
                "runtime_lineage_value_influence": lineage_value_count,
                "evidence_interpretation": (
                    "Activation, materialization, causal lineage, and fixed-order A/A/B value influence are prioritization signals. A/A/B is order-confounded; its HMAC authenticates the worker's redacted projection, not hostile-page truth. Only the execution oracle confirms XSS."
                ),
            },
        )
        db.add(observation)

        prior_confidence = float(hypothesis.confidence or 0.5)
        if hit:
            hypothesis.status = "supported"
            hypothesis.confidence = max(0.99, prior_confidence)
        else:
            hypothesis.status = "testing"
            if evidence_signal:
                hypothesis.confidence = min(
                    0.98,
                    prior_confidence + min(0.08, strength * 0.14),
                )
            else:
                hypothesis.confidence = max(0.05, prior_confidence * 0.985)

        tenant_id = hypothesis.experiment.target.tenant_id
        metadata = test_case.research_metadata if isinstance(test_case.research_metadata, dict) else {}
        fingerprint = metadata.get("context_fingerprint") or ResearchService.context_fingerprint(
            hypothesis, test_case.context, None
        )
        technique = test_case.technique or "unclassified"
        stat = db.query(ResearchTechniqueStat).filter_by(
            tenant_id=tenant_id, context_fingerprint=fingerprint, technique=technique
        ).first()
        if stat is None:
            stat = ResearchTechniqueStat(
                tenant_id=tenant_id,
                context_fingerprint=fingerprint,
                technique=technique,
                successes=0,
                failures=0,
                reward_sum=0.0,
            )
            db.add(stat)
        if hit:
            stat.successes += 1
        else:
            stat.failures += 1
        stat.reward_sum += strength
        stat.evidence = {
            "last_execution_id": execution.id,
            "last_hypothesis_id": hypothesis.id,
            "last_outcome": outcome,
        }
        llm_advice = metadata.get("llm_advice")
        if isinstance(llm_advice, dict):
            experiment = hypothesis.experiment
            limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
            brain_memory = dict(limits.get("campaign_brain") or {})
            performance = dict(brain_memory.get("llm_advisor_performance") or {})
            performance["executions"] = int(performance.get("executions") or 0) + 1
            performance["hits"] = int(performance.get("hits") or 0) + int(hit)
            performance["signals"] = int(performance.get("signals") or 0) + int(evidence_signal and not hit)
            performance["reward_sum"] = round(float(performance.get("reward_sum") or 0.0) + strength, 3)
            performance["last_execution_id"] = execution.id
            performance["model"] = str(llm_advice.get("model") or settings.LLM_MODEL)[:200]
            brain_memory["llm_advisor_performance"] = performance
            limits["campaign_brain"] = brain_memory
            experiment.limits = limits
        llm_pivot = metadata.get("llm_pivot")
        if isinstance(llm_pivot, dict):
            experiment = hypothesis.experiment
            limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
            brain_memory = dict(limits.get("campaign_brain") or {})
            performance = dict(brain_memory.get("llm_pivot_performance") or {})
            performance["executions"] = int(performance.get("executions") or 0) + 1
            performance["hits"] = int(performance.get("hits") or 0) + int(hit)
            performance["signals"] = int(performance.get("signals") or 0) + int(evidence_signal and not hit)
            performance["reward_sum"] = round(float(performance.get("reward_sum") or 0.0) + strength, 3)
            performance["last_execution_id"] = execution.id
            performance["model"] = str(llm_pivot.get("model") or settings.LLM_MODEL)[:200]
            performance["overrides"] = int(performance.get("overrides") or 0) + int(
                bool(llm_pivot.get("llm_changed_decision"))
            )
            brain_memory["llm_pivot_performance"] = performance
            limits["campaign_brain"] = brain_memory
            experiment.limits = limits

        # Shadow evaluation: if the deterministic baseline candidate later runs,
        # record its reward too. This makes LLM lift measurable without allowing
        # the model to control scope or fabricate a counterfactual result.
        experiment = hypothesis.experiment
        limits = dict(experiment.limits) if isinstance(experiment.limits, dict) else {}
        brain_memory = dict(limits.get("campaign_brain") or {})
        pivots = brain_memory.get("llm_pivots")
        pivots = pivots if isinstance(pivots, dict) else {}
        is_shadow_baseline = any(
            isinstance(record, dict)
            and record.get("llm_changed_decision")
            and record.get("deterministic_candidate_id") == test_case.id
            and record.get("selected_candidate_id") != test_case.id
            for record in pivots.values()
        )
        if is_shadow_baseline:
            performance = dict(brain_memory.get("llm_pivot_performance") or {})
            seen = list(performance.get("baseline_execution_ids") or [])
            if execution.id not in seen:
                performance["baseline_executions"] = int(performance.get("baseline_executions") or 0) + 1
                performance["baseline_hits"] = int(performance.get("baseline_hits") or 0) + int(hit)
                performance["baseline_reward_sum"] = round(
                    float(performance.get("baseline_reward_sum") or 0.0) + strength, 3
                )
                seen.append(execution.id)
                performance["baseline_execution_ids"] = seen[-100:]
                llm_runs = int(performance.get("executions") or 0)
                baseline_runs = int(performance.get("baseline_executions") or 0)
                if llm_runs and baseline_runs:
                    performance["observed_reward_lift"] = round(
                        float(performance.get("reward_sum") or 0.0) / llm_runs
                        - float(performance.get("baseline_reward_sum") or 0.0) / baseline_runs,
                        4,
                    )
                brain_memory["llm_pivot_performance"] = performance
                limits["campaign_brain"] = brain_memory
                experiment.limits = limits
        db.commit()
        return {
            "hypothesis_id": hypothesis.id,
            "status": hypothesis.status,
            "confidence": hypothesis.confidence,
            "technique": technique,
            "outcome": outcome,
        }

    @staticmethod
    def learn_from_findings(db: Session, experiment_id: int, findings: Iterable[Any]) -> int:
        """Promote direct-auditor hypotheses when independently verified evidence arrives."""
        aliases = {
            "open redirect": "open_redirect",
            "open_redirect": "open_redirect",
            "path traversal": "path_traversal",
            "path_traversal": "path_traversal",
            "lfi": "path_traversal",
            "sql injection": "sqli",
            "sqli": "sqli",
            "ssrf": "ssrf",
            "cors": "cors",
            "cors misconfiguration": "cors",
            "xss": "reflected_xss",
        }
        learned = 0
        for finding in findings:
            raw_type = str(getattr(finding, "vuln_type", "") or "").strip().lower().replace("-", "_")
            hypothesis_type = aliases.get(raw_type, aliases.get(raw_type.replace("_", " ")))
            if not hypothesis_type:
                continue
            query = db.query(ResearchHypothesis).filter(
                ResearchHypothesis.experiment_id == experiment_id,
                ResearchHypothesis.endpoint_id == finding.endpoint_id,
                ResearchHypothesis.hypothesis_type == hypothesis_type,
            )
            if finding.param_id is not None:
                query = query.filter(
                    (ResearchHypothesis.param_id == finding.param_id)
                    | (ResearchHypothesis.param_id.is_(None))
                )
            hypothesis = query.order_by(ResearchHypothesis.param_id.desc()).first()
            if hypothesis is None and hypothesis_type == "reflected_xss":
                hypothesis = db.query(ResearchHypothesis).filter(
                    ResearchHypothesis.experiment_id == experiment_id,
                    ResearchHypothesis.endpoint_id == finding.endpoint_id,
                    ResearchHypothesis.hypothesis_type.in_(["reflected_xss", "dom_xss"]),
                ).order_by(ResearchHypothesis.priority.desc()).first()
            if hypothesis is None:
                continue
            duplicate = db.query(ResearchObservation).filter_by(
                hypothesis_id=hypothesis.id, finding_id=finding.id
            ).first()
            if duplicate:
                continue
            db.add(ResearchObservation(
                hypothesis_id=hypothesis.id,
                finding_id=finding.id,
                signal_type="verified_finding",
                outcome="supported",
                strength=1.0,
                details={
                    "finding_type": raw_type,
                    "scanner_module": getattr(finding, "scanner_module", None),
                    "confidence": getattr(finding, "confidence", None),
                },
            ))
            hypothesis.status = "supported"
            hypothesis.confidence = max(0.99, float(hypothesis.confidence or 0.5))
            learned += 1
        if learned:
            db.commit()
        return learned
