"""Adaptive pruning — turn a polyglot triage result into request-budget savings.

The polyglot triage engine fires one mega-polyglot as Request #1 for a parameter. This service
consumes that probe's execution result and decides what to do with the parameter's *remaining*
speculative test cases:

* **Zero reflection** (token absent, and the response was not merely WAF-blocked) → the input is
  dead: cancel every pending/queued case for the parameter. This is the core rate-budget win.
* **Reflected residue** (token present, no execution) → keep fuzzing, but report the surviving
  contexts so the caller can narrow to those grammars.
* **Confirmed hit** → handled by the worker's own hit-prune path; this service defers to it.

Extracted from the worker so the decision is unit-testable without a live browser. The worker calls
:meth:`apply_triage_verdict` after it records each execution.
"""
from __future__ import annotations

from typing import Any, Dict

# HTTP statuses that mean "the WAF/app rejected the request", not "the input is dead". A polyglot is
# a big, obvious payload — a WAF may 403 it while a subtle single-context payload still reflects. We
# must NOT prune the parameter on these; doing so would discard reachable surface.
_BLOCKED_STATUSES = frozenset({403, 406, 429})


class AdaptivePruningService:
    @staticmethod
    def apply_triage_verdict(db: Any, test_case: Any, result: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a completed triage probe and prune the parameter's budget if it is dead.

        Returns a small trace dict (``applied``/``action``/``pruned``/``contexts``) for logging.
        No-op (``applied=False``) when the case is not a triage probe or the oracle already hit.
        """
        from fuzzer.polyglot_triage import PolyglotTriageEngine

        if result.get("oracle_hit"):
            # A confirmed execution is pruned by the worker's hit path with full evidence handling.
            return {"applied": False, "reason": "hit-handled-elsewhere"}
        if not PolyglotTriageEngine.is_triage_payload(getattr(test_case, "payload", "") or ""):
            return {"applied": False, "reason": "not-triage"}

        status = result.get("status_code")
        blocked = isinstance(status, int) and (status in _BLOCKED_STATUSES or status >= 500)

        verdict = PolyglotTriageEngine.evaluate_triage(
            dom_snapshot=result.get("dom_snapshot") or "",
            token=getattr(test_case, "token", None),
            oracle_executed=False,
        )

        # A taint signal in the logs means a DOM-XSS flow may exist even without server reflection —
        # never prune those; they are exactly the params the browser stage must keep exploring.
        logs_str = str(result.get("logs", ""))
        has_taint = "[TaintFlow]" in logs_str or "sink" in logs_str.lower()

        if verdict.recommended_strategy == "prune" and not has_taint and not blocked:
            from backend_api.models.test_case import TestCase, TestCaseStatus

            pruned = (
                db.query(TestCase)
                .filter(
                    TestCase.experiment_id == test_case.experiment_id,
                    TestCase.param_id == test_case.param_id,
                    TestCase.id != test_case.id,
                    TestCase.status.in_([TestCaseStatus.PENDING, TestCaseStatus.QUEUED]),
                )
                .update({"status": TestCaseStatus.CANCELLED}, synchronize_session=False)
            )
            db.commit()
            return {
                "applied": True,
                "action": "prune",
                "pruned": int(pruned or 0),
                "contexts": verdict.candidate_contexts,
                "notes": verdict.triage_notes,
            }

        # Reflected (or blocked/taint-guarded): keep the budget; surface the surviving contexts so
        # the campaign brain can narrow subsequent generation to grammars that actually survived.
        return {
            "applied": True,
            "action": "keep",
            "pruned": 0,
            "blocked": blocked,
            "reflected": verdict.reflected,
            "contexts": verdict.candidate_contexts,
            "notes": verdict.triage_notes,
        }
