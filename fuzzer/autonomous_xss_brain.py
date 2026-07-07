"""
Autonomous XSS Brain - Intelligent, context-aware reasoning and payload synthesis engine.

Combines real-time reflection analysis, filter constraints, CSP policy evaluation,
DOM sink graphs, and client-side framework signatures to synthesize the highest-probability
exploit chains automatically.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from fuzzer.payload_knowledge_base import (
    PayloadKnowledgeBase,
    PayloadEntry,
    XSSCategory,
    InjectionContext,
)
from fuzzer.mutation_engine import MutationEngine
from fuzzer.strategy import Strategy


@dataclass
class SynthesisDecision:
    """Detailed record of an autonomous reasoning decision."""
    payload: str
    category: XSSCategory
    confidence_score: float
    reasoning: str
    bypassed_constraints: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    cvss_score: float = 7.5


@dataclass
class BrainAnalysisReport:
    """Comprehensive intelligence report produced by AutonomousXSSBrain."""
    target_context: str
    primary_strategy: str
    detected_frameworks: List[str]
    identified_waf: Optional[str]
    csp_verdict: str
    total_candidates_synthesized: int
    top_payloads: List[SynthesisDecision]


class AutonomousXSSBrain:
    """
    Autonomous AI reasoning engine for Cross-Site Scripting.
    Translates threat modeling and vulnerability signals into optimal exploit payloads.
    """

    def __init__(self, callback_name: str = "__XSS__"):
        self.callback_name = callback_name
        self.knowledge_base = PayloadKnowledgeBase

    def synthesize_attack_chain(
        self,
        context_type: str,
        token: str,
        filter_profile: Optional[Dict[str, Any]] = None,
        csp_rules: Optional[Dict[str, Any]] = None,
        frameworks: Optional[List[str]] = None,
        sinks: Optional[List[str]] = None,
        strategy: Strategy = Strategy.SMART_ADAPTIVE,
        max_payloads: int = 50,
    ) -> BrainAnalysisReport:
        """
        Synthesize an optimized, ranked suite of XSS payloads tailored to the
        target's specific execution context and defense posture.
        """
        filter_prof = filter_profile or {}
        csp = csp_rules or {}
        fws = [f.lower().strip() for f in (frameworks or []) if f]
        detected_sinks = [s.lower().strip() for s in (sinks or []) if s]

        # Extract blocked characters and keywords
        blocked_chars: Set[str] = set()
        if "blocked_characters" in filter_prof:
            blocked_chars.update(filter_prof["blocked_characters"])
        if "char_filter" in filter_prof:
            for char, is_blocked in filter_prof["char_filter"].items():
                if is_blocked:
                    blocked_chars.add(char)

        # Detect WAF
        waf_detected = filter_prof.get("waf_name") or filter_prof.get("waf") or None
        if isinstance(waf_detected, str):
            waf_detected = waf_detected.lower().strip()

        # Map context string to InjectionContext enum
        mapped_context = self._map_context_string(context_type)

        decisions: List[SynthesisDecision] = []

        # -------------------------------------------------------------------------
        # Phase 1: Client-Side Template Injection (CSTI) Evaluation
        # -------------------------------------------------------------------------
        for fw in fws:
            csti_entries = self.knowledge_base.get_by_framework(fw)
            for entry in csti_entries:
                if entry.category == XSSCategory.CLIENT_TEMPLATE_INJECTION:
                    rendered = self.knowledge_base.render_payload(
                        entry.id, token, self.callback_name
                    )
                    decisions.append(
                        SynthesisDecision(
                            payload=rendered,
                            category=XSSCategory.CLIENT_TEMPLATE_INJECTION,
                            confidence_score=0.95,
                            reasoning=f"Target utilizes {fw}. Injected tailored CSTI sandbox escape: {entry.name}",
                            bypassed_constraints=["client_template_sandbox"],
                            tags=["csti", fw],
                            cvss_score=entry.cvss_score,
                        )
                    )

        # -------------------------------------------------------------------------
        # Phase 2: Context-Specific Breakout & Primary Knowledge Base Synthesis
        # -------------------------------------------------------------------------
        matching_entries = self.knowledge_base.find_matching_payloads(
            context=mapped_context,
            blocked_characters=blocked_chars,
            waf=waf_detected,
        )

        for entry in matching_entries:
            rendered = self.knowledge_base.render_payload(
                entry.id, token, self.callback_name
            )
            confidence = 0.85

            # Elevate score if it explicitly matches target WAF
            if waf_detected and waf_detected in [w.lower() for w in entry.bypasses_wafs]:
                confidence = 0.92

            decisions.append(
                SynthesisDecision(
                    payload=rendered,
                    category=entry.category,
                    confidence_score=confidence,
                    reasoning=f"Matched context {mapped_context.value} with {entry.name}",
                    bypassed_constraints=list(entry.blocked_chars_tolerated),
                    tags=entry.tags,
                    cvss_score=entry.cvss_score,
                )
            )

        # -------------------------------------------------------------------------
        # Phase 3: Character-Restricted Solver & Bypass Fallbacks
        # -------------------------------------------------------------------------
        if "<" in blocked_chars or ">" in blocked_chars:
            # Angle brackets blocked: prioritize attribute breakout or parentheseless/bracketless
            char_restricted = self.knowledge_base.get_by_category(XSSCategory.CHAR_RESTRICTED)
            for entry in char_restricted:
                if "no_angle_brackets" in entry.tags:
                    rendered = self.knowledge_base.render_payload(
                        entry.id, token, self.callback_name
                    )
                    decisions.append(
                        SynthesisDecision(
                            payload=rendered,
                            category=XSSCategory.CHAR_RESTRICTED,
                            confidence_score=0.90,
                            reasoning="Angle brackets < > are blocked. Using attribute/JS string bracketless breakout.",
                            bypassed_constraints=["no_angle_brackets"],
                            tags=["bracketless", "filter_bypass"],
                            cvss_score=entry.cvss_score,
                        )
                    )

        if "(" in blocked_chars or ")" in blocked_chars:
            # Parentheses blocked: prioritize onerror=eval;throw or tagged template literals
            char_restricted = self.knowledge_base.get_by_category(XSSCategory.CHAR_RESTRICTED)
            for entry in char_restricted:
                if "no_parentheses" in entry.tags:
                    rendered = self.knowledge_base.render_payload(
                        entry.id, token, self.callback_name
                    )
                    decisions.append(
                        SynthesisDecision(
                            payload=rendered,
                            category=XSSCategory.CHAR_RESTRICTED,
                            confidence_score=0.92,
                            reasoning="Parentheses ( ) are blocked. Using tagged template literal / throw error handler.",
                            bypassed_constraints=["no_parentheses"],
                            tags=["parentheseless", "filter_bypass"],
                            cvss_score=entry.cvss_score,
                        )
                    )

        # -------------------------------------------------------------------------
        # Phase 4: CSP Evaluation & Bypass Gadget Synthesis
        # -------------------------------------------------------------------------
        csp_verdict = "Permissive / No CSP"
        if csp:
            script_src = csp.get("script-src") or csp.get("default-src") or ""
            if script_src and "'unsafe-inline'" not in script_src:
                csp_verdict = "Strict CSP Active ('unsafe-inline' disabled)"
                # Generate CSP bypasses (JSONP, CDN angular, base-uri)
                csp_entries = self.knowledge_base.get_by_category(XSSCategory.CSP_BYPASS)
                for entry in csp_entries:
                    rendered = self.knowledge_base.render_payload(
                        entry.id, token, self.callback_name
                    )
                    decisions.append(
                        SynthesisDecision(
                            payload=rendered,
                            category=XSSCategory.CSP_BYPASS,
                            confidence_score=0.88,
                            reasoning=f"Active CSP without unsafe-inline. Synthesized CSP bypass gadget: {entry.name}",
                            bypassed_constraints=["csp_script_src"],
                            tags=["csp_bypass"],
                            cvss_score=entry.cvss_score,
                        )
                    )

        # -------------------------------------------------------------------------
        # Phase 5: DOM Clobbering & Prototype Pollution Gadgets
        # -------------------------------------------------------------------------
        if any("innerhtml" in s or "outerhtml" in s or "dompurify" in s for s in detected_sinks):
            # Ingest DOM clobbering & mXSS candidates
            clobber_entries = self.knowledge_base.get_by_category(XSSCategory.DOM_CLOBBERING)
            for entry in clobber_entries:
                rendered = self.knowledge_base.render_payload(
                    entry.id, token, self.callback_name
                )
                decisions.append(
                    SynthesisDecision(
                        payload=rendered,
                        category=XSSCategory.DOM_CLOBBERING,
                        confidence_score=0.82,
                        reasoning=f"Detected sensitive DOM sink. Synthesized DOM clobbering gadget: {entry.name}",
                        bypassed_constraints=["dom_sink_clobbering"],
                        tags=["dom_clobbering"],
                        cvss_score=entry.cvss_score,
                    )
                )

        # -------------------------------------------------------------------------
        # Phase 6: WAF Evasion Mutations
        # -------------------------------------------------------------------------
        if waf_detected:
            waf_entries = self.knowledge_base.get_by_category(XSSCategory.WAF_EVASION)
            for entry in waf_entries:
                rendered = self.knowledge_base.render_payload(
                    entry.id, token, self.callback_name
                )
                decisions.append(
                    SynthesisDecision(
                        payload=rendered,
                        category=XSSCategory.WAF_EVASION,
                        confidence_score=0.89,
                        reasoning=f"Target protected by {waf_detected}. Injected specialized WAF evasion vector: {entry.name}",
                        bypassed_constraints=[f"waf_{waf_detected}"],
                        tags=["waf_evasion", waf_detected],
                        cvss_score=entry.cvss_score,
                    )
                )

        # Deduplicate while preserving highest confidence
        unique_decisions: Dict[str, SynthesisDecision] = {}
        for d in decisions:
            if d.payload not in unique_decisions or d.confidence_score > unique_decisions[d.payload].confidence_score:
                unique_decisions[d.payload] = d

        sorted_decisions = sorted(
            unique_decisions.values(),
            key=lambda x: x.confidence_score,
            reverse=True,
        )[:max_payloads]

        return BrainAnalysisReport(
            target_context=mapped_context.value,
            primary_strategy=strategy.value if hasattr(strategy, "value") else str(strategy),
            detected_frameworks=fws,
            identified_waf=waf_detected,
            csp_verdict=csp_verdict,
            total_candidates_synthesized=len(sorted_decisions),
            top_payloads=sorted_decisions,
        )

    def _map_context_string(self, ctx_str: str) -> InjectionContext:
        """Map generic context string to InjectionContext enum."""
        c = (ctx_str or "").upper().strip()
        if "HTML_TEXT" in c:
            return InjectionContext.HTML_TEXT
        if "ATTR_QUOTED" in c:
            return InjectionContext.ATTR_QUOTED_DOUBLE
        if "ATTR_UNQUOTED" in c:
            return InjectionContext.ATTR_UNQUOTED
        if "EVENT_HANDLER" in c:
            return InjectionContext.EVENT_HANDLER_ATTR
        if "JS_STRING" in c:
            return InjectionContext.JS_STRING_DOUBLE
        if "TEMPLATE_LITERAL" in c or "JS_TEMPLATE" in c:
            return InjectionContext.JS_TEMPLATE_LITERAL
        if "JSON" in c:
            return InjectionContext.JSON_VALUE
        if "URL" in c:
            return InjectionContext.URL_QUERY
        if "CSS" in c:
            return InjectionContext.CSS_PROPERTY
        if "SVG" in c:
            return InjectionContext.SVG_NAMESPACE
        if "MATH" in c:
            return InjectionContext.MATHML_NAMESPACE
        return InjectionContext.HTML_TEXT
