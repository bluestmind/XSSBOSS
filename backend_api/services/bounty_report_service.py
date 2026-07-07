"""Bounty report generation from confirmed findings."""
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from backend_api.models.execution import Execution
from backend_api.models.finding import Finding
from backend_api.models.test_case import TestCase
from backend_api.utils.cvss_engine import CVSSEngine
from backend_api.utils.impact_scorer import ImpactScorer
from backend_api.services.poc_generator import PoCGenerator


class BountyReportService:
    """Build concise, impact-focused bounty reports for HackerOne, Bugcrowd, and internal triage."""

    @staticmethod
    def build_report(
        db: Session,
        finding: Finding,
        report_format: str = "hackerone"
    ) -> Dict[str, Any]:
        """Build a structured report for a finding with official CVSS 3.1 and standalone PoCs."""
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

        impact = impact or {}

        # 1. Calculate Official CVSS 3.1 Score and Vector
        is_stored = bool(verification.get("stored") or "stored-xss" in impact.get("tags", []))
        is_cross_role = bool(verification.get("cross_role") or "cross-role" in impact.get("tags", []))
        
        sev_str = str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity).upper()
        is_high_sev = sev_str in ("HIGH", "CRITICAL")

        can_hijack = is_high_sev or "high-value-surface" in impact.get("tags", []) or impact.get("score", 0) >= 65

        cvss_data = CVSSEngine.score_xss_finding(
            is_stored=is_stored,
            is_authenticated=bool(verification.get("authenticated")),
            is_cross_role=is_cross_role,
            can_hijack_session=can_hijack,
            can_modify_state=can_hijack,
            scope_changed=False
        )

        title = BountyReportService._title(finding, impact, cvss_data)
        summary = (
            f"The `{param.name}` parameter on `{endpoint.method} {endpoint.url_pattern}` "
            f"executes attacker-controlled JavaScript in a victim browser context, "
            f"potentially allowing session impersonation and account compromise."
        )

        if finding.evidence_summary:
            summary = f"{finding.evidence_summary}\n\n{summary}"
        elif is_stored:
            summary = (
                f"The `{param.name}` parameter on `{endpoint.method} {endpoint.url_pattern}` "
                "stores attacker-controlled JavaScript that executes persistently when affected pages are revisited, "
                "potentially compromising victim accounts without direct phishing."
            )
        if is_cross_role:
            summary += " Execution across different authenticated role contexts was verified."

        steps = BountyReportService._steps(finding, verification)
        evidence = BountyReportService._evidence(finding, executions, impact, cvss_data)

        # 2. Generate Standalone PoC Artifacts
        poc_html = PoCGenerator.generate_html_poc(
            method=endpoint.method,
            url=endpoint.url_pattern,
            param_name=param.name,
            payload=finding.best_payload or "",
            title=f"XSS PoC - {endpoint.url_pattern}"
        )
        poc_curl = PoCGenerator.generate_curl_command(
            method=endpoint.method,
            url=endpoint.url_pattern,
            param_name=param.name,
            payload=finding.best_payload or ""
        )

        remediation = [
            "Apply context-aware contextual output encoding (e.g. HTML entity, JavaScript attribute, or URL encoding) before rendering untrusted input.",
            "Avoid assigning user-controllable input to dangerous execution sinks such as `innerHTML`, `document.write`, `eval`, `Function`, or navigation sinks (`location.href`).",
            "Enforce a restrictive Content Security Policy (CSP) with strict script-src and object-src directives.",
            "Add automated regression tests covering this endpoint and parameter.",
        ]

        markdown = BountyReportService._markdown(
            title=title,
            summary=summary,
            cvss_data=cvss_data,
            impact=impact,
            steps=steps,
            evidence=evidence,
            poc_curl=poc_curl,
            poc_html=poc_html,
            remediation=remediation,
            payload=finding.best_payload or "",
            report_format=report_format
        )

        # Sanitize report to ensure zero markdown formatting archaeology
        clean_markdown = PoCGenerator.sanitize_markdown_report(markdown)

        return {
            "title": title,
            "summary": summary,
            "cvss": cvss_data,
            "impact": impact,
            "steps": steps,
            "evidence": evidence,
            "poc_html": poc_html,
            "poc_curl": poc_curl,
            "remediation": remediation,
            "markdown": clean_markdown,
        }

    @staticmethod
    def _title(finding: Finding, impact: Dict[str, Any], cvss_data: Dict[str, Any]) -> str:
        endpoint = finding.endpoint
        prefix = "Stored XSS" if "stored-xss" in impact.get("tags", []) else "DOM XSS"
        if "cross-role" in impact.get("tags", []):
            prefix = "Cross-Role Stored XSS"
        return f"{prefix} in {endpoint.method} {endpoint.url_pattern} ({cvss_data['severity']} {cvss_data['score']})"

    @staticmethod
    def _steps(finding: Finding, verification: Dict[str, Any]) -> List[str]:
        if verification.get("steps") and isinstance(verification.get("steps"), list):
            return verification.get("steps")

        endpoint = finding.endpoint
        param = finding.param
        steps = [
            f"Send a `{endpoint.method}` request to `{endpoint.url_pattern}`.",
            f"Place the payload in `{param.name}` ({param.location}).",
            "Open the reproduction URL in a standard modern browser.",
            "Observe execution of the attacker JavaScript payload confirmed by evidence.",
        ]

        if verification.get("stored"):
            revisit_urls = verification.get("revisit_urls") or []
            steps = [
                f"Submit the payload through `{endpoint.method} {endpoint.url_pattern}` in `{param.name}`.",
                "Wait for the application to store the submitted value.",
                "Revisit the affected application route.",
                "Observe persistent JavaScript execution.",
            ]
            if revisit_urls:
                steps.insert(2, f"Tested revisit URL(s): {', '.join(revisit_urls)}.")

        if verification.get("cross_role"):
            steps.append("Repeat the revisit step with a second authenticated role session to confirm cross-account impact.")

        return steps

    @staticmethod
    def _evidence(
        finding: Finding,
        executions: List[Execution],
        impact: Dict[str, Any],
        cvss_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        return {
            "finding_id": finding.id,
            "severity": cvss_data.get("severity"),
            "cvss_score": cvss_data.get("score"),
            "cvss_vector": cvss_data.get("vector"),
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
        cvss_data: Dict[str, Any],
        impact: Dict[str, Any],
        steps: List[str],
        evidence: Dict[str, Any],
        poc_curl: str,
        poc_html: str,
        remediation: List[str],
        payload: str,
        report_format: str = "hackerone"
    ) -> str:
        step_text = "\n".join(f"{idx}. {step}" for idx, step in enumerate(steps, 1))
        remediation_text = "\n".join(f"- {item}" for item in remediation)
        tags = ", ".join(impact.get("tags", [])) or "browser-execution"
        rationale = "\n".join(f"- {item}" for item in impact.get("rationale", []))

        return f"""# {title}

## Summary
{summary}

## Severity & CVSS 3.1 Rating
- **Severity**: {cvss_data['severity']} ({cvss_data['score']})
- **CVSS 3.1 Vector**: `{cvss_data['vector']}`

## Steps To Reproduce
{step_text}

### Proof of Concept (cURL Command)
```bash
{poc_curl}
```

### Standalone HTML Exploit (PoC)
```html
{poc_html}
```

## Payload
```html
{payload}
```

## Impact
{impact.get('impact_summary', 'Confirmed browser JavaScript execution, potentially allowing session impersonation.')}

- Internal Impact Score: {impact.get('score', 'n/a')}
- Tags: {tags}

{rationale}

## Supporting Evidence
- Finding ID: {evidence.get('finding_id')}
- Execution IDs: {', '.join(str(item) for item in evidence.get('execution_ids', [])) or 'n/a'}
- Oracle tokens: {', '.join(evidence.get('oracle_tokens', [])) or 'n/a'}
- Screenshots: {', '.join(evidence.get('screenshots', [])) or 'n/a'}

## Remediation
{remediation_text}
"""
