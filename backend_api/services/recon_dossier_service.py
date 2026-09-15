"""Reusable, redacted recon dossier and cross-bug routing plan."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from backend_api.models.endpoint import Endpoint
from backend_api.models.finding import Finding
from backend_api.models.target import Target
from backend_api.services.bug_class_registry import BugClassRegistry


_RULES = {
    "sqli": {
        "terms": {"id", "ids", "query", "search", "filter", "sort", "order", "page", "user", "account", "item", "category"},
        "locations": {"query", "body", "json", "path"},
    },
    "ssrf": {
        "terms": {"url", "uri", "endpoint", "target", "dest", "destination", "callback", "webhook", "feed", "proxy", "fetch", "remote", "avatar", "image", "host", "domain"},
        "locations": {"query", "body", "json", "path"},
    },
    "open_redirect": {
        "terms": {"redirect", "redirecturl", "return", "returnurl", "next", "continue", "destination", "dest", "callback", "url"},
        "locations": {"query", "body", "json"},
    },
    "crlf": {
        "terms": {"redirect", "location", "url", "return", "next", "filename", "download", "header"},
        "locations": {"query", "body", "json", "header"},
    },
    "path_traversal": {
        "terms": {"file", "filename", "path", "folder", "dir", "directory", "page", "template", "include", "download", "document"},
        "locations": {"query", "body", "json", "path"},
    },
    "http_param": {
        "terms": set(),
        "locations": {"query", "body", "json"},
    },
    "dangling_markup": {
        "terms": set(),
        "locations": {"query", "body", "json", "path", "header", "cookie"},
    },
    "idor_bola": {
        "terms": {"id", "userid", "account", "accountid", "owner", "ownerid", "tenant", "team", "project", "order", "invoice"},
        "locations": {"query", "body", "json", "path"},
    },
    "command_injection": {
        "terms": {"cmd", "command", "exec", "execute", "shell", "process", "host", "hostname", "ping", "utility"},
        "locations": {"query", "body", "json", "path"},
    },
    "file_upload": {
        "terms": {"file", "filename", "upload", "attachment", "avatar", "image", "import", "document"},
        "locations": {"body", "json", "query"},
    },
}

_SECRET_TERMS = (
    r"authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|password|passwd|cookie"
)
_SECRET_NAME_RE = re.compile(rf"(?i)(?:{_SECRET_TERMS})")
_SECRET_ASSIGN_RE = re.compile(
    rf"(?i)({_SECRET_TERMS})([\"']?\s*[:=]\s*)([\"']?)([^\"'\r\n,;&}}<]+)"
)


def _text(value: Any, limit: int = 2000) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        try:
            value = json.dumps(value, sort_keys=True, default=str)
        except Exception:
            value = str(value)
    value = _SECRET_ASSIGN_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}[REDACTED]",
        value,
    )
    return value[:limit]


def _is_secret_name(value: str) -> bool:
    return bool(_SECRET_NAME_RE.search(value or ""))


def _redact_structured(value: Any) -> Any:
    """Recursively make live-recon observations JSON-safe and secret-safe."""
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            key_text = str(key)
            is_metadata = key_text.endswith(("_count", "_names", "_included", "_redacted"))
            redacted[key_text] = "[REDACTED]" if _is_secret_name(key_text) and not is_metadata else _redact_structured(item)
        return redacted
    if isinstance(value, (list, tuple, set)):
        return [_redact_structured(item) for item in value]
    if isinstance(value, str):
        return _text(value, 10_000)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _text(value, 10_000)


def _sha256_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True, default=str)
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _terms(name: str) -> set[str]:
    compact = re.sub(r"[^a-z0-9]+", "", (name or "").lower())
    split = set(filter(None, re.split(r"[^a-z0-9]+", (name or "").lower())))
    return split | ({compact} if compact else set())


class ReconDossierService:
    """Build one complete inventory that every vulnerability subsystem can reuse."""

    @staticmethod
    def _routes_for(endpoint: Endpoint) -> dict[str, list[dict[str, Any]]]:
        routes: dict[str, list[dict[str, Any]]] = {key: [] for key in BugClassRegistry.keys()}
        path = urlparse(endpoint.url_pattern or "").path.lower()
        response = (endpoint.sample_response_body or "").lower()

        # Endpoint-wide checks do not require a parameter candidate.
        routes["cors"].append({"param_id": None, "reason": "HTTP endpoint exposes a cross-origin trust boundary"})
        if endpoint.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            routes["csrf"].append({"param_id": None, "reason": "state-changing HTTP method"})
        if "graphql" in path:
            routes["graphql_auth"].append({"param_id": None, "reason": "GraphQL endpoint requires field/object authorization differentials"})
        if _SECRET_NAME_RE.search(endpoint.sample_response_body or ""):
            routes["client_secret_exposure"].append({"param_id": None, "reason": "redacted secret-like response indicator"})
        if endpoint.method.upper() in {"GET", "HEAD"} and (
            endpoint.auth_context or any(term in path for term in ("account", "profile", "dashboard", "settings", "api"))
        ):
            routes["cache_deception"].append({"param_id": None, "reason": "cacheable-looking authenticated or sensitive GET route"})

        contexts_by_param: dict[int, list[Any]] = {}
        for context in endpoint.contexts or []:
            contexts_by_param.setdefault(context.param_id, []).append(context)

        for param in endpoint.params or []:
            pterms = _terms(param.name)
            location = (param.location or "").lower()
            contexts = contexts_by_param.get(param.id, [])
            if param.is_controllable:
                routes["xss"].append({
                    "param_id": param.id,
                    "reason": "controllable input" + (f" with {len(contexts)} reflection context(s)" if contexts else ""),
                })
            for key, rule in _RULES.items():
                if location not in rule["locations"]:
                    continue
                matched = sorted(pterms & rule["terms"])
                if rule["terms"] and not matched:
                    continue
                if key == "dangling_markup" and contexts and not any(
                    str(context.context_type).startswith(("HTML", "ATTR", "URL", "SRC_DOC"))
                    for context in contexts
                ):
                    continue
                routes[key].append({
                    "param_id": param.id,
                    "reason": f"{location} parameter" + (f" matched {', '.join(matched)}" if matched else " supports differential probing"),
                })

        # Response evidence can promote markup testing even before contexts exist.
        if response and "<html" in response and not routes["dangling_markup"]:
            for param in endpoint.params or []:
                if param.is_controllable:
                    routes["dangling_markup"].append({"param_id": param.id, "reason": "HTML response with controllable input"})
        return {key: values for key, values in routes.items() if values}

    @staticmethod
    def build(
        db: Session,
        target_id: int,
        *,
        endpoint_ids: Optional[Iterable[int]] = None,
        observations: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        target = db.query(Target).filter(Target.id == target_id).first()
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        query = db.query(Endpoint).filter(Endpoint.target_id == target_id)
        selected_ids = list(dict.fromkeys(int(value) for value in (endpoint_ids or []) if value is not None))
        if selected_ids:
            query = query.filter(Endpoint.id.in_(selected_ids))
        endpoints = query.order_by(Endpoint.id.asc()).all()

        coverage: dict[str, dict[str, Any]] = {
            bug.key: {
                "name": bug.name,
                "kind": bug.kind,
                "candidate_endpoint_ids": [],
                "candidate_param_ids": [],
                "candidate_count": 0,
            }
            for bug in BugClassRegistry.all()
        }
        inventory = []
        technologies: set[str] = set()

        for endpoint in endpoints:
            path = urlparse(endpoint.url_pattern or "").path.lower()
            response_lower = (endpoint.sample_response_body or "").lower()
            if "graphql" in path:
                technologies.add("GraphQL")
            if any(marker in path for marker in ("openapi", "swagger", "api-docs")):
                technologies.add("OpenAPI")
            for marker, label in (("__next", "Next.js"), ("ng-version", "Angular"), ("data-reactroot", "React"), ("__nuxt", "Nuxt")):
                if marker in response_lower:
                    technologies.add(label)

            routes = ReconDossierService._routes_for(endpoint)
            for bug_key, candidates in routes.items():
                bucket = coverage[bug_key]
                bucket["candidate_endpoint_ids"].append(endpoint.id)
                bucket["candidate_param_ids"].extend(
                    item["param_id"] for item in candidates if item.get("param_id") is not None
                )
                bucket["candidate_count"] += len(candidates)

            inventory.append({
                "id": endpoint.id,
                "method": endpoint.method.upper(),
                "url": endpoint.url_pattern,
                "discovered_at": endpoint.discovered_at.isoformat() if endpoint.discovered_at else None,
                "authentication_context_present": bool(endpoint.auth_context),
                "authentication_header_names": sorted((endpoint.auth_context or {}).keys()) if isinstance(endpoint.auth_context, dict) else [],
                "request_sample": _text(endpoint.sample_request_body),
                "request_sample_sha256": _sha256_text(endpoint.sample_request_body),
                "response_excerpt": _text(endpoint.sample_response_body),
                "response_body_bytes": len((endpoint.sample_response_body or "").encode("utf-8", errors="ignore")),
                "response_body_sha256": _sha256_text(endpoint.sample_response_body),
                "response_excerpt_truncated": len(endpoint.sample_response_body or "") > 2000,
                "custom_steps": _redact_structured(endpoint.custom_steps or []),
                "parameters": [
                    {
                        "id": param.id,
                        "name": param.name,
                        "location": param.location,
                        "controllable": bool(param.is_controllable),
                        "burp_flagged": bool(param.burp_flagged),
                        "sample": "[REDACTED]" if _is_secret_name(param.name) else _text(param.sample_value, 300),
                    }
                    for param in endpoint.params or []
                ],
                "contexts": [
                    {
                        "id": context.id,
                        "param_id": context.param_id,
                        "type": context.context_type,
                        "tag": context.tag,
                        "attribute": context.attribute,
                        "script_path": context.script_path,
                        "detected_at": context.detected_at.isoformat() if context.detected_at else None,
                        "snippet": _text(context.snippet, 700),
                        "sinks": [
                            {
                                "id": sink.id,
                                "type": sink.sink_type,
                                "location": sink.js_location,
                                "detected_via": sink.detected_via.value if hasattr(sink.detected_via, "value") else str(sink.detected_via),
                                "taint_path": sink.taint_path or [],
                                "notes": _text(sink.notes, 1000),
                            }
                            for sink in context.sinks or []
                        ],
                    }
                    for context in endpoint.contexts or []
                ],
                "findings": [
                    {
                        "id": finding.id,
                        "param_id": finding.param_id,
                        "context_id": finding.context_id,
                        "sink_id": finding.sink_id,
                        "type": finding.vuln_type,
                        "scanner_module": finding.scanner_module,
                        "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                        "status": finding.status.value if hasattr(finding.status, "value") else str(finding.status),
                        "confidence": finding.confidence,
                        "evidence": _text(finding.evidence_summary, 1000),
                        "best_payload": _text(finding.best_payload, 5000),
                        "report_text": _text(finding.report_text, 5000),
                        "evidence_refs": _redact_structured(finding.evidence_refs or {}),
                        "poc_request": _redact_structured(finding.poc_request or {}),
                        "poc_html_excerpt": _text(finding.poc_html, 5000),
                        "screenshot_path": finding.screenshot_path,
                        "observations": [
                            {
                                "id": observation.id,
                                "experiment_id": observation.experiment_id,
                                "test_case_id": observation.test_case_id,
                                "execution_id": observation.execution_id,
                                "evidence": _redact_structured(observation.evidence or {}),
                            }
                            for observation in finding.observations or []
                        ],
                        "evidence_artifacts": [
                            {
                                "id": artifact.id,
                                "experiment_id": artifact.experiment_id,
                                "execution_id": artifact.execution_id,
                                "kind": artifact.kind,
                                "uri": artifact.uri,
                                "sha256": artifact.sha256,
                                "size_bytes": artifact.size_bytes,
                                "metadata": _redact_structured(artifact.artifact_metadata or {}),
                            }
                            for artifact in finding.evidence_artifacts or []
                        ],
                    }
                    for finding in endpoint.findings or []
                ],
                "bug_class_routes": routes,
            })

        for bucket in coverage.values():
            bucket["candidate_endpoint_ids"] = list(dict.fromkeys(bucket["candidate_endpoint_ids"]))
            bucket["candidate_param_ids"] = list(dict.fromkeys(bucket["candidate_param_ids"]))

        param_count = sum(len(item["parameters"]) for item in inventory)
        context_count = sum(len(item["contexts"]) for item in inventory)
        sink_count = sum(len(context["sinks"]) for item in inventory for context in item["contexts"])
        finding_count = sum(len(item["findings"]) for item in inventory)
        generated = datetime.now(UTC).isoformat()
        payload = {
            "schema_version": 2,
            "generated_at": generated,
            "target": {
                "id": target.id,
                "name": target.name,
                "base_url": target.base_url,
                "status": target.status.value if hasattr(target.status, "value") else str(target.status),
                "bounty_platform": target.bounty_platform,
                "scope": target.scope_tags or {},
            },
            "summary": {
                "endpoints": len(inventory),
                "parameters": param_count,
                "contexts": context_count,
                "sinks": sink_count,
                "findings": finding_count,
                "technologies": sorted(technologies),
                "bug_classes": len(coverage),
            },
            "coverage_matrix": coverage,
            "endpoints": inventory,
            "recon_observations": _redact_structured(observations or {}),
            "redaction": {
                "raw_auth_values_included": False,
                "secret_like_values_redacted": True,
            },
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        payload["integrity_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return payload

    @staticmethod
    def prioritize_endpoints(endpoints: Iterable[Endpoint], dossier: dict[str, Any], bug_key: str) -> list[Endpoint]:
        """Put recon-selected candidates first while retaining complete coverage."""
        values = list(endpoints)
        candidate_ids = set(
            dossier.get("coverage_matrix", {}).get(bug_key, {}).get("candidate_endpoint_ids", [])
        )
        return sorted(values, key=lambda endpoint: (endpoint.id not in candidate_ids, endpoint.id))

    @staticmethod
    def export(dossier: dict[str, Any], path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(dossier, indent=2, default=str), encoding="utf-8")
        return path
