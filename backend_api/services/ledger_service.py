"""Ledger service — turn a finished experiment into an honest coverage verdict.

Wires the reachability ledger into the live flow: for each (param, context) an experiment tested,
it reads the oracle outcomes and classifies the epistemic state — CONFIRMED_VULN (a HIT),
INCONCLUSIVE (fired but no execution observed), or UNREACHED (never executed). The result is a
coverage report that refuses to claim "clean" while any input is still undecided.

(PROVEN_SAFE — SMT UNSAT — is not persisted per context yet, so it is not asserted here; those
contexts land in INCONCLUSIVE, which correctly keeps the verdict conservative rather than
over-claiming safety.)
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from analysis_engine.reachability_ledger import ReachabilityLedger, classify
from backend_api.models.context import Context
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.param import Param
from backend_api.models.test_case import TestCase


class LedgerService:
    """Builds a ReachabilityLedger from an experiment's persisted results."""

    @staticmethod
    def build_for_experiment(db: Session, experiment_id: int) -> ReachabilityLedger:
        ledger = ReachabilityLedger()
        test_cases = db.query(TestCase).filter(TestCase.experiment_id == experiment_id).all()
        if not test_cases:
            return ledger

        groups: Dict[tuple, List[int]] = defaultdict(list)
        for tc in test_cases:
            groups[(tc.param_id, tc.context_id)].append(tc.id)

        param_names: Dict[int, str] = {}
        ctx_names: Dict[int, str] = {}

        for (param_id, context_id), tc_ids in groups.items():
            execs = db.query(Execution).filter(Execution.test_case_id.in_(tc_ids)).all()
            hit = any(e.oracle_status == OracleStatus.HIT for e in execs)
            fired = len(execs) > 0

            if param_id not in param_names:
                p = db.query(Param).filter(Param.id == param_id).first()
                param_names[param_id] = p.name if p else f"param#{param_id}"
            if context_id and context_id not in ctx_names:
                c = db.query(Context).filter(Context.id == context_id).first()
                ctx_names[context_id] = c.context_type if c else "UNKNOWN"

            certainty = classify(oracle_hit=hit, smt_proven_safe=False, fired=fired)
            ledger.record(
                param=param_names[param_id],
                context=ctx_names.get(context_id, "UNKNOWN"),
                certainty=certainty,
                evidence=f"{len(execs)} execution(s), {len(tc_ids)} payload(s)",
            )
        return ledger

    @classmethod
    def coverage_for_experiment(cls, db: Session, experiment_id: int) -> Dict[str, Any]:
        """The honest headline: what fraction of the tested surface has a decided answer."""
        ledger = cls.build_for_experiment(db, experiment_id)
        return {
            "experiment_id": experiment_id,
            "coverage": ledger.coverage(),
            "confirmed": ledger.confirmed(),
            "gaps": ledger.gaps(),
            "trustworthy_clean": ledger.is_trustworthy_clean(),
        }
