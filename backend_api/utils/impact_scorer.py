"""Impact scoring helpers for bounty triage."""
from typing import Any, Dict, List, Optional

from backend_api.models.context import Context
from backend_api.models.endpoint import Endpoint
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.finding import Severity
from backend_api.models.param import Param
from backend_api.models.sink import Sink
from backend_api.models.test_case import TestCase


HIGH_VALUE_TERMS = {
    "admin": 18,
    "moderator": 16,
    "support": 14,
    "staff": 14,
    "billing": 16,
    "payment": 16,
    "checkout": 14,
    "invoice": 12,
    "oauth": 15,
    "sso": 15,
    "saml": 15,
    "login": 10,
    "session": 12,
    "token": 12,
    "invite": 13,
    "webhook": 12,
    "template": 12,
    "email": 11,
    "notification": 10,
    "message": 10,
    "comment": 9,
    "profile": 8,
    "settings": 9,
    "account": 10,
    "team": 8,
    "organization": 8,
    "workspace": 8,
    "ticket": 10,
}

HIGH_VALUE_PARAMS = {
    "redirect": 8,
    "return": 6,
    "next": 6,
    "url": 6,
    "callback": 8,
    "template": 10,
    "message": 8,
    "comment": 7,
    "bio": 6,
    "name": 5,
    "email": 6,
    "html": 8,
    "content": 7,
    "description": 7,
}

ROLE_TERMS = ("admin", "owner", "staff", "support", "moderator", "triage")


class ImpactScorer:
    """Score confirmed XSS based on execution proof and bounty-relevant impact."""

    @staticmethod
    def score_attack_surface(
        endpoint: Endpoint,
        param: Optional[Param] = None,
        context: Optional[Context] = None,
    ) -> Dict[str, Any]:
        """Score an unconfirmed endpoint/parameter for fuzzing priority."""
        text = f"{endpoint.url_pattern} {param.name if param else ''}".lower()
        score = 0
        tags: List[str] = []

        for term, weight in HIGH_VALUE_TERMS.items():
            if term in text:
                score += min(weight, 12)

        if param:
            param_name = (param.name or "").lower()
            for term, weight in HIGH_VALUE_PARAMS.items():
                if term in param_name:
                    score += min(weight, 8)

        if context:
            if context.context_type in ("JS_STRING_LITERAL", "JS_IDENTIFIER"):
                score += 8
                tags.append("script-context")
            elif context.context_type in ("EVENT_HANDLER_ATTR", "ATTR_UNQUOTED"):
                score += 6
                tags.append("attribute-execution-context")
            elif context.context_type == "HTML_TEXT":
                score += 3
                tags.append("html-context")

        if endpoint.method and endpoint.method.upper() in ("POST", "PUT", "PATCH"):
            score += 5
            tags.append("state-changing-endpoint")

        if score:
            tags.append("bounty-priority")

        return {
            "score": min(score, 40),
            "tags": list(dict.fromkeys(tags)),
        }

    @staticmethod
    def score_test_case(
        test_case: TestCase,
        execution: Optional[Execution] = None,
        sink: Optional[Sink] = None,
        verification: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return impact score, severity, tags, and rationale for a test case."""
        endpoint = test_case.endpoint
        param = test_case.param
        context = test_case.context
        return ImpactScorer.score_components(
            endpoint=endpoint,
            param=param,
            context=context,
            execution=execution,
            sink=sink,
            verification=verification,
        )

    @staticmethod
    def score_components(
        endpoint: Endpoint,
        param: Param,
        context: Optional[Context] = None,
        execution: Optional[Execution] = None,
        sink: Optional[Sink] = None,
        verification: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a structured bounty impact score."""
        verification = verification or {}
        tags: List[str] = []
        rationale: List[str] = []
        score = 0

        has_oracle_hit = execution is None or execution.oracle_status == OracleStatus.HIT
        if has_oracle_hit:
            score += 35
            tags.append("browser-execution")
            rationale.append("Payload reached real browser JavaScript execution.")

        text = f"{endpoint.url_pattern} {param.name}".lower()
        matched_terms = []
        for term, weight in HIGH_VALUE_TERMS.items():
            if term in text:
                score += weight
                matched_terms.append(term)
        if matched_terms:
            tags.append("high-value-surface")
            rationale.append(f"Endpoint/parameter suggests sensitive workflow: {', '.join(sorted(set(matched_terms)))}.")

        param_terms = []
        param_name = (param.name or "").lower()
        for term, weight in HIGH_VALUE_PARAMS.items():
            if term in param_name:
                score += weight
                param_terms.append(term)
        if param_terms:
            tags.append("impactful-parameter")
            rationale.append(f"Parameter name suggests security-relevant behavior: {', '.join(sorted(set(param_terms)))}.")

        context_type = context.context_type if context else None
        if context_type in ("JS_STRING_LITERAL", "JS_IDENTIFIER"):
            score += 12
            tags.append("script-context")
            rationale.append("Input lands in a JavaScript execution context.")
        elif context_type in ("EVENT_HANDLER_ATTR", "ATTR_UNQUOTED"):
            score += 9
            tags.append("attribute-execution-context")
            rationale.append("Input lands in an executable HTML attribute context.")
        elif context_type == "HTML_TEXT":
            score += 5
            tags.append("html-context")
            rationale.append("Input lands in raw HTML output.")

        if sink:
            score += 12
            tags.append("dangerous-sink")
            rationale.append(f"Input is associated with sink: {sink.sink_type}.")

        if verification.get("stored"):
            score += 20
            tags.append("stored-xss")
            rationale.append("Payload was verified after revisiting a page, indicating stored execution.")

        if verification.get("cross_role"):
            score += 18
            tags.append("cross-role")
            rationale.append("Payload executed in a different session or role context.")

        roles = [str(role).lower() for role in verification.get("roles", [])]
        privileged_roles = [role for role in roles if any(term in role for term in ROLE_TERMS)]
        if privileged_roles:
            score += 15
            tags.append("privileged-viewer")
            rationale.append(f"Execution reached privileged viewer role(s): {', '.join(privileged_roles)}.")

        if endpoint.method and endpoint.method.upper() in ("POST", "PUT", "PATCH"):
            score += 5
            tags.append("state-changing-endpoint")
            rationale.append("Payload enters through a state-changing endpoint.")

        score = min(score, 100)
        severity = ImpactScorer._severity_for_score(score)

        return {
            "score": score,
            "severity": severity,
            "severity_value": severity.value,
            "tags": list(dict.fromkeys(tags)),
            "rationale": rationale,
            "impact_summary": ImpactScorer._impact_summary(score, verification, tags),
        }

    @staticmethod
    def _severity_for_score(score: int) -> Severity:
        if score >= 85:
            return Severity.CRITICAL
        if score >= 65:
            return Severity.HIGH
        if score >= 40:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _impact_summary(score: int, verification: Dict[str, Any], tags: List[str]) -> str:
        if verification.get("cross_role"):
            return "Confirmed XSS execution across user or role boundary, suitable for high-impact bounty triage."
        if verification.get("stored"):
            return "Confirmed stored XSS execution after revisiting the affected page."
        if "high-value-surface" in tags or score >= 65:
            return "Confirmed browser execution on a sensitive application surface."
        return "Confirmed browser execution. Impact depends on reachable user actions and data in this context."
