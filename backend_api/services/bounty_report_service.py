"""Bounty report generation from confirmed findings."""
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from backend_api.models.execution import Execution
from backend_api.models.finding import Finding
from backend_api.models.test_case import TestCase
from backend_api.utils.impact_scorer import ImpactScorer


class BountyReportService:
    """Build concise, impact-focused bounty reports."""

    @staticmethod
    def build_report(db: Session, finding: Finding) -> Dict[str, Any]:
        """Build a structured report for a finding."""
        endpoint = finding.endpoint
        param = finding.param
        context = finding.context
        evidence_refs = finding.evidence_refs or {}

        execution_ids = evidence_refs.get("execution_ids") or []
        executions: List[Execution] = []
        if execution_ids:
            executions = db.query(Execution).filter(Execution.id.in_(execution_ids)).all()

        test_case = None
        if evidence_refs.get("test_case_id"):
            test_case = db.query(TestCase).filter(TestCase.id == evidence_refs["test_case_id"]).first()

        verification = evidence_refs.get("verification") or {}
        impact = evidence_refs.get("impact")
        if not impact and test_case:
            impact = ImpactScorer.score_test_case(
                test_case,
                execution=executions[0] if executions else None,
                sink=finding.sink,
                verification=verification,
            )

        title = BountyReportService._title(finding, impact or {})
        summary = (
            f"The `{param.name}` parameter on `{endpoint.method} {endpoint.url_pattern}` "
            f"executes attacker-controlled JavaScript in a victim browser."
        )

        if verification.get("stored"):
            summary = (
                f"The `{param.name}` parameter on `{endpoint.method} {endpoint.url_pattern}` "
                "can store attacker-controlled JavaScript that executes when the affected page is revisited."
            )
        if verification.get("cross_role"):
            summary += " The proof shows execution across a different session or role context."

        steps = BountyReportService._steps(finding, verification)
        evidence = BountyReportService._evidence(finding, executions, impact or {})
        remediation = [
            "Apply output encoding for the exact rendering context before inserting user-controlled data.",
            "Avoid assigning user input to HTML/JavaScript sinks such as innerHTML, document.write, eval, Function, or string-based timers.",
            "Add a restrictive Content Security Policy as a defense-in-depth control.",
            "Add regression tests for this parameter and context.",
        ]

        markdown = BountyReportService._markdown(
            title=title,
            summary=summary,
            impact=impact or {},
            steps=steps,
            evidence=evidence,
            remediation=remediation,
            payload=finding.best_payload,
        )

        return {
            "title": title,
            "summary": summary,
            "impact": impact,
            "steps": steps,
            "evidence": evidence,
            "remediation": remediation,
            "markdown": markdown,
        }

    @staticmethod
    def _title(finding: Finding, impact: Dict[str, Any]) -> str:
        endpoint = finding.endpoint
        context = finding.context.context_type if finding.context else "unknown context"
        prefix = "Stored XSS" if "stored-xss" in impact.get("tags", []) else "XSS"
        if "cross-role" in impact.get("tags", []):
            prefix = "Cross-Role Stored XSS"
        return f"{prefix} in {endpoint.method} {endpoint.url_pattern} ({context})"

    @staticmethod
    def _steps(finding: Finding, verification: Dict[str, Any]) -> List[str]:
        endpoint = finding.endpoint
        param = finding.param
        steps = [
            f"Send a `{endpoint.method}` request to `{endpoint.url_pattern}`.",
            f"Place the payload in `{param.name}` ({param.location}).",
            "Open the affected page in a browser with the same application context.",
            "Observe JavaScript execution confirmed by the oracle evidence.",
        ]

        if verification.get("stored"):
            revisit_urls = verification.get("revisit_urls") or []
            steps = [
                f"Submit the payload through `{endpoint.method} {endpoint.url_pattern}` in `{param.name}`.",
                "Wait for the application to store/render the submitted value.",
                "Revisit the affected page or viewer route.",
                "Observe JavaScript execution confirmed by the oracle evidence.",
            ]
            if revisit_urls:
                steps.insert(2, f"Tested revisit URL(s): {', '.join(revisit_urls)}.")

        if verification.get("cross_role"):
            steps.append("Repeat the revisit step with the second authorized role/session to confirm cross-account impact.")

        return steps

    @staticmethod
    def _evidence(finding: Finding, executions: List[Execution], impact: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "finding_id": finding.id,
            "severity": finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
            "impact_score": impact.get("score"),
            "impact_tags": impact.get("tags", []),
            "execution_ids": [execution.id for execution in executions],
            "oracle_tokens": [execution.oracle_token for execution in executions if execution.oracle_token],
            "screenshots": [execution.screenshot_path for execution in executions if execution.screenshot_path],
            "poc_request": finding.poc_request,
        }

    @staticmethod
    def _markdown(
        title: str,
        summary: str,
        impact: Dict[str, Any],
        steps: List[str],
        evidence: Dict[str, Any],
        remediation: List[str],
        payload: str,
    ) -> str:
        step_text = "\n".join(f"{idx}. {step}" for idx, step in enumerate(steps, 1))
        remediation_text = "\n".join(f"- {item}" for item in remediation)
        tags = ", ".join(impact.get("tags", [])) or "browser-execution"
        rationale = "\n".join(f"- {item}" for item in impact.get("rationale", []))

        return f"""# {title}

## Summary
{summary}

## Impact
{impact.get('impact_summary', 'Confirmed browser JavaScript execution.')}

- Impact score: {impact.get('score', 'n/a')}
- Suggested severity: {impact.get('severity_value', 'n/a')}
- Tags: {tags}

{rationale}

## Payload
```html
{payload}
```

## Steps To Reproduce
{step_text}

## Evidence
- Finding ID: {evidence.get('finding_id')}
- Execution IDs: {', '.join(str(item) for item in evidence.get('execution_ids', [])) or 'n/a'}
- Oracle tokens: {', '.join(evidence.get('oracle_tokens', [])) or 'n/a'}
- Screenshots: {', '.join(evidence.get('screenshots', [])) or 'n/a'}

## Remediation
{remediation_text}
"""
