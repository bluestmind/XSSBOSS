"""Bypass decider — reason before you fire.

A dumb fuzzer sends its whole payload set at every context and hopes. A hunter reasons: given the
filter I *observed on this target* (which characters/tokens it strips), can a bypass exist here at
all? This consults the SMT string solver with the live filter evidence and returns a decision:

* **SKIP**  — the solver *proved UNSAT*: no payload of any modeled breakout shape can survive this
  filter in this context. Don't spend a single browser execution on it. (Formal, not a guess.)
* **FIRE_WITNESS** — SAT: a concrete bypass exists; fire it first (the generator front-loads it).
* **NORMAL** — no recipe for the context, no filter evidence, or the solver was unsure: fuzz as usual.

This turns the solver from a payload source into a *decision procedure that gates expensive work*,
which is where winrate-per-time is won: no executions wasted on provably-unbypassable contexts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from analysis_engine.smt_bypass_solver import FilterConstraints, SMTBypassSolver, SolveStatus


class Decision(str, Enum):
    SKIP = "skip"
    FIRE_WITNESS = "fire_witness"
    NORMAL = "normal"


# fuzzer ContextType value -> the SMT solver's recipe context string.
_CONTEXT_MAP: Dict[str, str] = {
    "HTML_TEXT": "HTML_TEXT",
    "HTML_COMMENT": "COMMENT_BLOCK",
    "HTML_RCDATA": "HTML_TEXT",
    "HTML_RAW_TEXT": "HTML_TEXT",
    "SRC_DOC_ATTR": "HTML_TEXT",
    "ATTR_QUOTED": "ATTR_QUOTED_DOUBLE",
    "ATTR_UNQUOTED": "ATTR_UNQUOTED",
    "EVENT_HANDLER_ATTR": "EVENT_HANDLER_ATTR",
    "URL_QUERY": "URL_QUERY",
    "URL_FRAGMENT": "URL_FRAGMENT",
    "JS_STRING_LITERAL": "JS_STRING_DOUBLE",
    "JS_TEMPLATE_LITERAL": "JS_TEMPLATE_LITERAL",
    "JS_IDENTIFIER": "JS_BLOCK",
    "SVG_TEXT": "SVG_NAMESPACE",
    "MATHML_TEXT": "MATHML_NAMESPACE",
    "CSS_STYLE_BLOCK": "STYLE_BLOCK",
    "JSON_VALUE": "JSON_VALUE",
    "JSON_KEY": "JSON_VALUE",
}


@dataclass
class BypassVerdict:
    decision: Decision
    smt_context: str = ""
    witness: Optional[str] = None
    proof: List[str] = field(default_factory=list)   # unsat core, when SKIP
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value, "smt_context": self.smt_context,
            "witness": self.witness, "proof": self.proof, "rationale": self.rationale,
        }


class BypassDecider:
    """Decides, per (context, observed filter), whether fuzzing this context can ever pay off."""

    @staticmethod
    def _constraints(filter_profile: Optional[Dict[str, Any]]) -> Optional[FilterConstraints]:
        fp = filter_profile or {}
        blocked_tokens = set(fp.get("blocked_tokens", []) or [])
        blocked_chars = set(fp.get("blocked_chars", []) or [])
        if not blocked_tokens and not blocked_chars:
            return None  # no observed filter evidence -> nothing to reason about
        return FilterConstraints(
            blocked_substrings=blocked_tokens,
            blocked_chars=blocked_chars,
            blocked_regexes=list(fp.get("waf_regexes", []) or []),
            max_length=fp.get("max_reflection_length"),
        )

    @classmethod
    def decide(cls, context_type: str, filter_profile: Optional[Dict[str, Any]],
               token: str = "{TOKEN}") -> BypassVerdict:
        smt_ctx = _CONTEXT_MAP.get(str(context_type))
        if not smt_ctx:
            return BypassVerdict(Decision.NORMAL, rationale=f"no SMT recipe for context '{context_type}'")

        # No filter evidence still yields the canonical payload for the context (open reflection is
        # the highest-confidence XSS — hand over the exploit, don't punt to blind fuzzing).
        constraints = cls._constraints(filter_profile)
        open_context = constraints is None
        if constraints is None:
            constraints = FilterConstraints()

        sol = SMTBypassSolver().solve(smt_ctx, constraints, token)
        if sol.status == SolveStatus.UNSAT:
            return BypassVerdict(
                Decision.SKIP, smt_ctx, proof=list(sol.unsat_core),
                rationale="proven unbypassable in this context under the observed filter",
            )
        if sol.status == SolveStatus.SAT and sol.witness:
            why = ("open reflection — canonical payload for this context"
                   if open_context else f"bypass proven via recipe '{sol.recipe}' — fire it first")
            return BypassVerdict(Decision.FIRE_WITNESS, smt_ctx, witness=sol.witness, rationale=why)
        return BypassVerdict(Decision.NORMAL, smt_ctx, rationale="solver undecided — fuzz normally")
