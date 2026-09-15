"""Reachability ledger — the epistemics of 100% winrate: never falsely report "clean".

A scanner that returns "no XSS found" is lying by omission: it conflates *proven safe* with *not
tested* with *tested inconclusively*. This ledger keeps them apart. Every (param, context) lands in
exactly one epistemic state, built from the ground-truth signals the pipeline already produces:

* **CONFIRMED_VULN**  — the execution oracle observed JS run. Certain YES, with proof.
* **PROVEN_SAFE**     — the SMT solver returned UNSAT for the observed filter. Certain NO, with proof.
* **INCONCLUSIVE**    — payloads fired, nothing executed, but no proof of safety. *Unknown.*
* **UNREACHED**       — never navigated/tested. *Unknown.*

"Winrate" then becomes measurable: the **decided fraction** (confirmed + proven-safe). You approach
100% by shrinking INCONCLUSIVE + UNREACHED — and, crucially, you never claim a clean bill of health
you can't back. The ledger hands a human the exact undecided surface to close, ranked by value.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Certainty(str, Enum):
    CONFIRMED_VULN = "confirmed_vuln"   # oracle observed execution — proof of YES
    PROVEN_SAFE = "proven_safe"         # SMT UNSAT — proof of NO
    INCONCLUSIVE = "inconclusive"       # fired, no hit, no safety proof — unknown
    UNREACHED = "unreached"             # never tested — unknown


_DECIDED = {Certainty.CONFIRMED_VULN, Certainty.PROVEN_SAFE}
# severity weight so the "gaps to close" list surfaces the highest-value unknowns first.
_CTX_VALUE = {
    "JS_STRING_LITERAL": 5, "JS_IDENTIFIER": 5, "EVENT_HANDLER_ATTR": 5,
    "HTML_TEXT": 4, "SRC_DOC_ATTR": 4, "URL_QUERY": 3, "ATTR_QUOTED": 3,
}


def classify(*, oracle_hit: bool, smt_proven_safe: bool, fired: bool) -> Certainty:
    """Map raw pipeline signals to an epistemic state. Order matters: proof beats absence."""
    if oracle_hit:
        return Certainty.CONFIRMED_VULN
    if smt_proven_safe:
        return Certainty.PROVEN_SAFE
    if fired:
        return Certainty.INCONCLUSIVE
    return Certainty.UNREACHED


@dataclass
class LedgerEntry:
    param: str
    context: str
    certainty: Certainty
    reachable: bool = False          # did code analysis prove it reaches a sink?
    evidence: str = ""

    @property
    def is_decided(self) -> bool:
        return self.certainty in _DECIDED

    @property
    def value(self) -> int:
        v = _CTX_VALUE.get(self.context, 2)
        return v + (3 if self.reachable else 0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "param": self.param, "context": self.context, "certainty": self.certainty.value,
            "reachable": self.reachable, "decided": self.is_decided, "evidence": self.evidence,
        }


@dataclass
class ReachabilityLedger:
    entries: List[LedgerEntry] = field(default_factory=list)

    def record(self, param: str, context: str, certainty: Certainty,
               reachable: bool = False, evidence: str = "") -> LedgerEntry:
        e = LedgerEntry(param, context, certainty, reachable, evidence)
        self.entries.append(e)
        return e

    def record_signals(self, param: str, context: str, *, oracle_hit: bool = False,
                       smt_proven_safe: bool = False, fired: bool = False,
                       reachable: bool = False, evidence: str = "") -> LedgerEntry:
        return self.record(param, context, classify(oracle_hit=oracle_hit,
                           smt_proven_safe=smt_proven_safe, fired=fired), reachable, evidence)

    # ---- the numbers that define "how close to 100%" -------------------------

    def counts(self) -> Dict[str, int]:
        out = {c.value: 0 for c in Certainty}
        for e in self.entries:
            out[e.certainty.value] += 1
        return out

    def coverage(self) -> Dict[str, Any]:
        total = len(self.entries)
        decided = sum(1 for e in self.entries if e.is_decided)
        confirmed = sum(1 for e in self.entries if e.certainty is Certainty.CONFIRMED_VULN)
        return {
            "total": total,
            "counts": self.counts(),
            # Fraction of the surface where we KNOW the answer (found or provably safe).
            "decided_fraction": round(decided / total, 4) if total else 1.0,
            "confirmed_vulnerabilities": confirmed,
            # The honest headline: we can only claim "clean" over the decided-safe surface.
            "undecided": total - decided,
            "clean_claim_valid_over": round(decided / total, 4) if total else 1.0,
        }

    def is_trustworthy_clean(self) -> bool:
        """True only if there are no confirmed vulns AND nothing is left undecided.

        This is the guard against a false "clean": we refuse to certify a target safe while any
        input remains INCONCLUSIVE or UNREACHED.
        """
        return all(e.certainty is Certainty.PROVEN_SAFE for e in self.entries) and bool(self.entries)

    def gaps(self, limit: int = 20) -> List[Dict[str, Any]]:
        """The undecided surface to close to push winrate toward 100%, highest-value first."""
        undecided = [e for e in self.entries if not e.is_decided]
        undecided.sort(key=lambda e: (-e.value, e.param, e.context))
        return [e.to_dict() for e in undecided[:limit]]

    def confirmed(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self.entries if e.certainty is Certainty.CONFIRMED_VULN]
