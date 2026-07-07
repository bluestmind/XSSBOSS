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
import re
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
from backend_api.services.run_state_service import RunStateService
from backend_api.utils.impact_scorer import ImpactScorer
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


class ResearchService:
    @staticmethod
    def _fingerprint(*parts: Any) -> str:
        normalized = "|".join("" if part is None else str(part) for part in parts)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

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
        }
        endpoint_nodes: dict[int, AttackSurfaceNode] = {}
        endpoints_by_path: dict[str, list[Endpoint]] = {}
        for endpoint in endpoints:
            path = urlparse(endpoint.url_pattern).path.rstrip("/") or "/"
            endpoints_by_path.setdefault(path, []).append(endpoint)

        for signal in list(recon_signals)[:250]:
            if not isinstance(signal, dict) or signal.get("kind") != "client_bundle":
                continue
            script_url = str(signal.get("script_url") or "")[:2000]
            if not script_url:
                continue
            counts = signal.get("counts") if isinstance(signal.get("counts"), dict) else {}
            normalized_counts = {
                key: max(0, min(100_000, int(counts.get(key, 0) or 0)))
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
                + normalized_counts["prototype_pollution"] * 6,
            )
            script_node = ResearchService._node(
                db,
                experiment_id,
                "client_script",
                script_key,
                script_url,
                script_risk,
                {
                    "size_bytes": max(0, int(signal.get("size_bytes", 0) or 0)),
                    "counts": normalized_counts,
                },
            )
            ResearchService._edge(db, experiment_id, target_node, script_node, "loads", 1.0)

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

            for route in list(signal.get("discovered_endpoints") or [])[:50]:
                route_path = urlparse(str(route)).path.rstrip("/") or "/"
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
        if totals["postmessage_listeners"]:
            ResearchService._hypothesis(
                db, experiment_id, "postmessage_boundary",
                "Cross-origin postMessage trust boundary",
                "Client bundles register message handlers. Verify origin/source validation and trace message-controlled data into navigation or DOM sinks with harmless canaries.",
                None, None, None, 0.52, min(100, 45 + totals["postmessage_listeners"] * 3),
                ["origin-validation", "source-validation", "message-shape-differential", "dynamic-taint-confirmation"],
                {"listener_count": totals["postmessage_listeners"]},
            )
        if totals["prototype_pollution"]:
            ResearchService._hypothesis(
                db, experiment_id, "prototype_pollution",
                "Prototype mutation primitives in client code",
                "Static primitives may expose a property-injection path. Use non-destructive marker properties and require an observable gadget effect before promotion.",
                None, None, None, 0.34, min(100, 40 + totals["prototype_pollution"] * 4),
                ["marker-property", "merge-path-differential", "gadget-confirmation"],
                {"primitive_count": totals["prototype_pollution"]},
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
            "selected_technique": selected_technique,
            "context_fingerprint": context_fingerprint,
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
        logs = result.get("logs")
        if not isinstance(logs, dict):
            try:
                logs = json.loads(execution.logs or "{}")
            except (TypeError, ValueError, json.JSONDecodeError):
                logs = {}
        sink_signal = bool(logs.get("sink") or logs.get("sinks") or logs.get("auditor_vuln"))
        outcome = "supported" if hit else ("signal" if sink_signal else "inconclusive")
        strength = 1.0 if hit else (0.35 if sink_signal else 0.0)
        observation = ResearchObservation(
            hypothesis_id=hypothesis.id,
            execution_id=execution.id,
            signal_type="browser_execution" if hit else ("sink_telemetry" if sink_signal else "negative_probe"),
            outcome=outcome,
            strength=strength,
            details={
                "oracle_status": execution.oracle_status.value,
                "technique": test_case.technique,
                "duration_ms": execution.duration_ms,
                "status_code": result.get("status_code"),
            },
        )
        db.add(observation)

        prior_confidence = float(hypothesis.confidence or 0.5)
        if hit:
            hypothesis.status = "supported"
            hypothesis.confidence = max(0.99, prior_confidence)
        else:
            hypothesis.status = "testing"
            hypothesis.confidence = min(0.98, prior_confidence + 0.04) if sink_signal else max(0.05, prior_confidence * 0.985)

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
