"""SARIF report service — emit findings in SARIF 2.1.0 (dalfox-parity for CI/security tooling).

SARIF is the standard result format that GitHub code scanning, DefectDojo, and most security
dashboards ingest. This converts XSSBOSS findings into it, so a run drops straight into a pipeline.
Pure transform over finding dicts; a DB helper builds those from Finding records.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# severity -> SARIF level
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


class SarifReportService:
    SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

    @classmethod
    def build(cls, findings: List[Dict[str, Any]], tool_version: str = "1.0") -> Dict[str, Any]:
        """Build a SARIF 2.1.0 log from a list of finding dicts.

        Each finding may carry: rule_id/vuln_type, severity, url, param, payload, message, context.
        """
        rules: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for f in findings or []:
            rule_id = str(f.get("rule_id") or f.get("vuln_type") or "xss")
            severity = str(f.get("severity") or "medium").lower()
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id.replace("_", " ").title().replace(" ", ""),
                    "shortDescription": {"text": f.get("rule_desc") or rule_id.replace("_", " ").upper()},
                    "defaultConfiguration": {"level": _LEVEL.get(severity, "warning")},
                }
            url = f.get("url") or f.get("endpoint") or ""
            message = f.get("message") or f.get("description") or f"{rule_id} at {f.get('param') or url}"
            result: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": _LEVEL.get(severity, "warning"),
                "message": {"text": str(message)},
                "properties": {k: f[k] for k in ("severity", "param", "payload", "context", "finding_id")
                               if f.get(k) is not None},
            }
            if url:
                result["locations"] = [{
                    "physicalLocation": {"artifactLocation": {"uri": url}},
                    "logicalLocations": [{"name": f["param"], "kind": "parameter"}] if f.get("param") else [],
                }]
            results.append(result)

        return {
            "$schema": cls.SCHEMA,
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "XSSBoss",
                    "version": tool_version,
                    "informationUri": "https://xssboss.local",
                    "rules": list(rules.values()),
                }},
                "results": results,
            }],
        }

    @classmethod
    def build_for_experiment(cls, db: Any, experiment_id: int) -> Dict[str, Any]:
        """Build SARIF from an experiment's Finding records (defensive against schema differences)."""
        from backend_api.models.endpoint import Endpoint
        from backend_api.models.finding import Finding

        rows = (
            db.query(Finding)
            .join(Endpoint, Finding.endpoint_id == Endpoint.id)
            .filter(Endpoint.target_id.isnot(None))
            .all()
        )
        findings: List[Dict[str, Any]] = []
        for r in rows:
            sev = getattr(r, "severity", None)
            findings.append({
                "finding_id": getattr(r, "id", None),
                "rule_id": getattr(r, "vuln_type", None) or "xss",
                "severity": (sev.value if hasattr(sev, "value") else str(sev or "medium")).lower(),
                "url": getattr(getattr(r, "endpoint", None), "url_pattern", None),
                "param": getattr(getattr(r, "param", None), "name", None),
                "payload": getattr(r, "payload", None),
                "description": getattr(r, "description", None) or getattr(r, "title", None),
            })
        return cls.build(findings)
