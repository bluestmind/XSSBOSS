"""Evidence-driven control loop for autonomous security campaigns.

The rest of XSSBOSS produces useful evidence: hypotheses, taint paths, sink
telemetry, filter profiles, browser outcomes, and cross-run technique stats.
This service turns those signals into the next action.  It intentionally stays
deterministic and explainable; an operator can see why every case was selected.
"""
from __future__ import annotations

import math
import os
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.experiment import Experiment
from backend_api.models.research import ResearchTechniqueStat
from backend_api.models.sink import Sink
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.config import settings
from backend_api.utils.log_serializer import (
    parse_execution_logs,
    sanitize_execution_logs,
)
from backend_api.utils.logger import logger


@dataclass
class CaseUtility:
    test_case: TestCase
    score: float
    expected_success: float
    information_gain: float
    reasons: List[str] = field(default_factory=list)

    def public(self) -> Dict[str, Any]:
        return {
            "test_case_id": self.test_case.id,
            "score": round(self.score, 3),
            "expected_success": round(self.expected_success, 4),
            "information_gain": round(self.information_gain, 4),
            "reasons": self.reasons[:8],
        }


class SmartCampaignBrain:
    """Select, observe, learn, and re-plan without hiding the reasoning."""

    MODEL_VERSION = "utility-loop-v2-llm-pivot"
    MAX_TRACE = 100

    @staticmethod
    def _has_signal(logs: Any) -> bool:
        text = str(logs or "").lower()
        return any(marker in text for marker in (
            "taintflow", "\"sink\"", "'sink'", "auditor_vuln",
            "reflection", "dom_mutation", "oracle",
        ))

    @staticmethod
    def _group_key(case: TestCase) -> tuple[int, int, Optional[int]]:
        return (case.endpoint_id, case.param_id, case.context_id)

    @classmethod
    def _history(cls, db: Session, experiment_id: int) -> Dict[tuple, Dict[str, Any]]:
        rows = (
            db.query(TestCase, Execution)
            .outerjoin(Execution, Execution.test_case_id == TestCase.id)
            .filter(TestCase.experiment_id == experiment_id)
            .all()
        )
        history: Dict[tuple, Dict[str, Any]] = defaultdict(lambda: {
            "attempts": 0,
            "hits": 0,
            "signals": 0,
            "techniques": Counter(),
            "durations": [],
        })
        seen_executions = set()
        for case, execution in rows:
            if execution is None or execution.id in seen_executions:
                continue
            seen_executions.add(execution.id)
            item = history[cls._group_key(case)]
            item["attempts"] += 1
            technique = case.technique or "unclassified"
            item["techniques"][technique] += 1
            if execution.oracle_status == OracleStatus.HIT:
                item["hits"] += 1
            if cls._has_signal(execution.logs):
                item["signals"] += 1
            if execution.duration_ms is not None:
                item["durations"].append(max(0, int(execution.duration_ms)))
        return history

    @classmethod
    def _technique_prior(
        cls,
        db: Session,
        case: TestCase,
    ) -> tuple[float, int]:
        hypothesis = case.research_hypothesis
        if hypothesis is None or not case.technique:
            return 0.5, 0
        tenant_id = hypothesis.experiment.target.tenant_id
        metadata = case.research_metadata if isinstance(case.research_metadata, dict) else {}
        fingerprint = metadata.get("context_fingerprint")
        if not fingerprint:
            return 0.5, 0
        stat = db.query(ResearchTechniqueStat).filter_by(
            tenant_id=tenant_id,
            context_fingerprint=fingerprint,
            technique=case.technique,
        ).first()
        if stat is None:
            return 0.5, 0
        uses = int(stat.successes or 0) + int(stat.failures or 0)
        # Beta(1,1) posterior: stable with small samples and never becomes 0/1.
        return (float(stat.successes or 0) + 1.0) / (uses + 2.0), uses

    @classmethod
    def score_case(
        cls,
        db: Session,
        case: TestCase,
        history: Optional[Dict[tuple, Dict[str, Any]]] = None,
        sink_counts: Optional[Dict[int, int]] = None,
        technique_priors: Optional[Dict[tuple[str, str], tuple[float, int]]] = None,
    ) -> CaseUtility:
        history = history or cls._history(db, case.experiment_id)
        group = history.get(cls._group_key(case), {})
        attempts = int(group.get("attempts", 0))
        hits = int(group.get("hits", 0))
        signals = int(group.get("signals", 0))
        techniques = group.get("techniques") or Counter()
        technique = case.technique or "unclassified"
        same_technique_attempts = int(techniques.get(technique, 0))

        hypothesis = case.research_hypothesis
        hypothesis_confidence = float(getattr(hypothesis, "confidence", 0.5) or 0.5)
        impact = float(getattr(hypothesis, "impact_score", 35) or 35)
        metadata = case.research_metadata if isinstance(case.research_metadata, dict) else {}
        prior_key = (str(metadata.get("context_fingerprint") or ""), technique)
        posterior, prior_uses = (
            technique_priors.get(prior_key, (0.5, 0))
            if technique_priors is not None
            else cls._technique_prior(db, case)
        )
        # Blend target-specific belief with cross-run technique evidence.
        expected_success = 0.55 * posterior + 0.45 * hypothesis_confidence
        information_gain = 4.0 * expected_success * (1.0 - expected_success)

        reasons: List[str] = []
        score = min(160.0, max(-50.0, float(case.priority or 0))) * 0.42
        score += expected_success * 38.0
        score += information_gain * 18.0
        score += min(100.0, impact) * 0.24

        if hypothesis is not None:
            reasons.append(
                f"hypothesis={hypothesis.hypothesis_type} confidence={hypothesis_confidence:.2f}"
            )
        if prior_uses:
            reasons.append(f"learned technique posterior={posterior:.2f} over {prior_uses} runs")
        else:
            reasons.append("untried technique preserves exploration")
            score += 9.0

        sink_count = 0
        if case.context_id is not None:
            sink_count = (
                int(sink_counts.get(case.context_id, 0))
                if sink_counts is not None
                else db.query(Sink).filter(Sink.context_id == case.context_id).count()
            )
        if sink_count:
            score += min(24.0, 12.0 + sink_count * 4.0)
            reasons.append(f"{sink_count} reachable sink signal(s)")
        if bool(getattr(case.param, "taint_reachable", False)):
            score += 18.0
            reasons.append("static/dynamic taint says the parameter reaches a sink")
        if signals:
            score += min(20.0, 8.0 + signals * 4.0)
            reasons.append(f"{signals} earlier partial execution signal(s); pivot, do not abandon")

        if same_technique_attempts:
            score -= min(30.0, same_technique_attempts * 9.0)
            reasons.append(f"repeat penalty: technique already tried {same_technique_attempts} time(s)")
        score -= min(18.0, attempts * 2.0)

        durations = group.get("durations") or []
        if durations:
            average_ms = sum(durations) / len(durations)
            cost_penalty = min(12.0, average_ms / 2500.0)
            score -= cost_penalty
            reasons.append(f"runtime cost penalty={cost_penalty:.1f}")
        if hits:
            score -= 10_000.0
            reasons.append("context already confirmed; redundant execution")

        return CaseUtility(case, score, expected_success, information_gain, reasons)

    @classmethod
    def select_batch(
        cls,
        db: Session,
        experiment: Experiment,
        candidates: Sequence[TestCase],
        slots: int,
    ) -> List[TestCase]:
        """Choose a high-utility *diverse* batch, not merely the largest integers."""
        if slots <= 0 or not candidates:
            return []
        history = cls._history(db, experiment.id)
        context_ids = {case.context_id for case in candidates if case.context_id is not None}
        sink_counts = {
            context_id: int(count)
            for context_id, count in (
                db.query(Sink.context_id, func.count(Sink.id))
                .filter(Sink.context_id.in_(context_ids))
                .group_by(Sink.context_id)
                .all()
                if context_ids else []
            )
        }
        fingerprints = {
            str((case.research_metadata or {}).get("context_fingerprint"))
            for case in candidates
            if isinstance(case.research_metadata, dict)
            and (case.research_metadata or {}).get("context_fingerprint")
        }
        tenant_id = experiment.target.tenant_id
        technique_priors: Dict[tuple[str, str], tuple[float, int]] = {}
        if fingerprints:
            for stat in db.query(ResearchTechniqueStat).filter(
                ResearchTechniqueStat.tenant_id == tenant_id,
                ResearchTechniqueStat.context_fingerprint.in_(fingerprints),
            ).all():
                uses = int(stat.successes or 0) + int(stat.failures or 0)
                technique_priors[(stat.context_fingerprint, stat.technique)] = (
                    (float(stat.successes or 0) + 1.0) / (uses + 2.0),
                    uses,
                )
        remaining = [
            cls.score_case(db, case, history, sink_counts, technique_priors)
            for case in candidates
        ]
        selected: List[CaseUtility] = []
        endpoint_uses: Counter = Counter()
        param_uses: Counter = Counter()
        context_uses: Counter = Counter()

        while remaining and len(selected) < slots:
            def marginal(item: CaseUtility) -> float:
                case = item.test_case
                return (
                    item.score
                    - endpoint_uses[case.endpoint_id] * 4.0
                    - param_uses[case.param_id] * 10.0
                    - context_uses[cls._group_key(case)] * 14.0
                )

            winner = max(remaining, key=lambda item: (marginal(item), -item.test_case.id))
            remaining.remove(winner)
            selected.append(winner)
            endpoint_uses[winner.test_case.endpoint_id] += 1
            param_uses[winner.test_case.param_id] += 1
            context_uses[cls._group_key(winner.test_case)] += 1

        now = datetime.now(UTC).isoformat()
        for item in selected:
            metadata = dict(item.test_case.research_metadata or {})
            metadata["brain"] = {**item.public(), "selected_at": now}
            item.test_case.research_metadata = metadata

        limits = dict(experiment.limits or {})
        memory = dict(limits.get("campaign_brain") or {})
        memory.update({
            "model": cls.MODEL_VERSION,
            "last_selection_at": now,
            "last_selection": [item.public() for item in selected],
            "pending_candidates_considered": len(candidates),
        })
        limits["campaign_brain"] = memory
        experiment.limits = limits
        return [item.test_case for item in selected]

    @classmethod
    def _apply_llm_pivot(
        cls,
        db: Session,
        execution: Execution,
        result: Dict[str, Any],
        siblings: Sequence[TestCase],
    ) -> Optional[Dict[str, Any]]:
        """Apply one cached, allowlisted LLM pivot to pending deterministic work."""
        if not siblings:
            return None
        case = execution.test_case
        experiment = case.experiment
        technique = case.technique or "unclassified"
        cache_key = f"{case.endpoint_id}:{case.param_id}:{case.context_id}:{technique}"
        limits = dict(experiment.limits or {})
        memory = dict(limits.get("campaign_brain") or {})
        if limits.get("llm_mode") == "deterministic_only" or memory.get("llm_unavailable"):
            return None
        pivots = dict(memory.get("llm_pivots") or {})
        if cache_key in pivots:
            return {**dict(pivots[cache_key]), "cached": True, "applied": False}
        calls = int(memory.get("llm_pivot_calls") or 0)
        if calls >= max(0, int(settings.LLM_MIDSCAN_MAX_CALLS)):
            return None

        history = cls._history(db, case.experiment_id)
        group_history = history.get(cls._group_key(case), {})
        ranked = [cls.score_case(db, sibling, history) for sibling in siblings]
        deterministic_candidate_id = max(
            ranked, key=lambda item: (item.score, -item.test_case.id)
        ).test_case.id
        candidates = [
            {
                "id": item.test_case.id,
                "technique": item.test_case.technique or "unclassified",
                "utility": item.score,
                "expected_success": item.expected_success,
                "information_gain": item.information_gain,
                "prior_attempts": int(
                    (group_history.get("techniques") or {}).get(
                        item.test_case.technique or "unclassified", 0
                    )
                ),
            }
            for item in ranked
        ]
        raw_runtime_logs = result.get("logs") or execution.logs
        parsed_runtime_logs = (
            raw_runtime_logs
            if isinstance(raw_runtime_logs, Mapping)
            else parse_execution_logs(raw_runtime_logs)
        )
        safe_runtime_logs = sanitize_execution_logs(
            parsed_runtime_logs,
            test_case_id=execution.test_case_id,
            attempt_no=execution.attempt_no,
        )
        evidence = {
            "trigger_test_case_id": case.id,
            "executed_technique": technique,
            "oracle_status": execution.oracle_status.value,
            "runtime_logs": safe_runtime_logs,
            "status_code": result.get("status_code"),
            "attempts_in_context": int(group_history.get("attempts") or 0),
            "signals_in_context": int(group_history.get("signals") or 0),
            "techniques_tried": dict(group_history.get("techniques") or {}),
        }
        from backend_api.services.llm_service import LLMService
        from backend_api.services.log_service import LogService

        LogService.info(
            "llm.advisor",
            f"Requesting bounded LLM pivot advice for test case #{case.id}",
            experiment_id=case.experiment_id,
            target_id=experiment.target_id,
            data={
                "event_type": "llm_pivot_requested",
                "model": settings.LLM_MODEL,
                "cache_key": cache_key,
                "trigger_test_case_id": case.id,
                "candidate_count": len(candidates),
                "candidate_ids": [item["id"] for item in candidates],
                "evidence": evidence,
            },
            db=db,
        )

        advice = LLMService.advise_pivot(evidence, candidates)
        selected_id = advice.get("selected_candidate_id")
        selected = next((sibling for sibling in siblings if sibling.id == selected_id), None)
        applied = False
        applied_priority_boost = 0
        confidence = float(advice.get("confidence") or 0.0)
        if selected is not None and confidence >= max(0.0, settings.LLM_MIDSCAN_MIN_CONFIDENCE):
            raw_boost = int(advice.get("priority_boost") or 0)
            performance = memory.get("llm_pivot_performance")
            performance = performance if isinstance(performance, dict) else {}
            performance_runs = int(performance.get("executions") or 0)
            reward_mean = (
                float(performance.get("reward_sum") or 0.0) / performance_runs
                if performance_runs else 0.0
            )
            # Once there is enough local evidence, reward useful LLM pivots and
            # shrink weak ones. Deterministic utility remains the baseline.
            multiplier = max(0.5, min(1.5, 0.5 + reward_mean)) if performance_runs >= 4 else 1.0
            boost = max(0, min(20, round(raw_boost * multiplier)))
            selected.priority += boost
            applied_priority_boost = boost
            metadata = dict(selected.research_metadata or {})
            metadata["llm_pivot"] = {
                "model": settings.LLM_MODEL,
                "trigger_test_case_id": case.id,
                "cache_key": cache_key,
                "deterministic_candidate_id": deterministic_candidate_id,
                "llm_changed_decision": selected.id != deterministic_candidate_id,
                "priority_boost": boost,
                "raw_priority_boost": raw_boost,
                "calibration_multiplier": round(multiplier, 3),
                "confidence": advice.get("confidence"),
                "rationale": advice.get("rationale"),
            }
            selected.research_metadata = metadata
            applied = True
        elif selected is not None:
            advice = {
                **advice,
                "rationale": (
                    f"Rejected below confidence gate ({confidence:.2f} < "
                    f"{settings.LLM_MIDSCAN_MIN_CONFIDENCE:.2f})."
                ),
            }

        record = {
            **advice,
            "applied_priority_boost": applied_priority_boost,
            "deterministic_candidate_id": deterministic_candidate_id,
            "candidate_ids": [item.test_case.id for item in ranked[:24]],
            "llm_changed_decision": bool(
                selected_id is not None and selected_id != deterministic_candidate_id
            ),
            "trigger_test_case_id": case.id,
            "at": datetime.now(UTC).isoformat(),
            "cached": False,
            "applied": applied,
        }
        pivots[cache_key] = record
        memory["llm_pivots"] = dict(list(pivots.items())[-50:])
        memory["llm_pivot_calls"] = calls + 1
        memory["last_llm_pivot"] = record
        limits["campaign_brain"] = memory
        experiment.limits = limits
        LogService.info(
            "llm.advisor",
            f"LLM pivot advice processed for test case #{case.id}",
            experiment_id=case.experiment_id,
            target_id=experiment.target_id,
            data={
                "event_type": "llm_pivot_result",
                "model": settings.LLM_MODEL,
                "selected_candidate_id": selected_id,
                "deterministic_candidate_id": deterministic_candidate_id,
                "changed_decision": record["llm_changed_decision"],
                "applied": applied,
                "confidence": advice.get("confidence"),
                "rationale": advice.get("rationale"),
            },
            db=db,
        )
        return record

    @classmethod
    def observe(
        cls,
        db: Session,
        execution: Execution,
        result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update campaign memory and pending action values after one real outcome."""
        result = result or {}
        case = execution.test_case
        experiment = case.experiment
        hit = execution.oracle_status == OracleStatus.HIT
        signal = cls._has_signal(result.get("logs") or execution.logs)
        technique = case.technique or "unclassified"

        siblings = db.query(TestCase).filter(
            TestCase.experiment_id == case.experiment_id,
            TestCase.endpoint_id == case.endpoint_id,
            TestCase.param_id == case.param_id,
            TestCase.context_id == case.context_id,
            TestCase.status == TestCaseStatus.PENDING,
        ).all()
        action = "confirm_and_stop_redundant"
        rationale = "execution oracle confirmed the hypothesis"
        adjusted = 0
        llm_pivot = None

        if not hit and signal:
            action = "pivot_on_partial_signal"
            rationale = "the probe reached interesting behavior; favor a different technique"
            for sibling in siblings:
                sibling.priority += 12 if (sibling.technique or "unclassified") != technique else -4
                adjusted += 1
            if (
                settings.LLM_ENABLED
                and settings.LLM_MIDSCAN_ADVISOR
                and not os.getenv("PYTEST_CURRENT_TEST")
            ):
                try:
                    llm_pivot = cls._apply_llm_pivot(db, execution, result, siblings)
                    if llm_pivot and llm_pivot.get("applied"):
                        action = "llm_guided_pivot"
                        rationale = str(llm_pivot.get("rationale") or rationale)
                except Exception as pivot_error:
                    llm_pivot = {"error": str(pivot_error)[:300], "applied": False}
                    limits = dict(experiment.limits or {})
                    memory = dict(limits.get("campaign_brain") or {})
                    memory["llm_pivot_calls"] = int(memory.get("llm_pivot_calls") or 0) + 1
                    memory["llm_pivot_failures"] = int(memory.get("llm_pivot_failures") or 0) + 1
                    memory["llm_unavailable"] = True
                    memory["last_llm_error"] = str(pivot_error)[:300]
                    memory["last_llm_error_at"] = datetime.now(UTC).isoformat()
                    limits["campaign_brain"] = memory
                    limits["llm_mode"] = "deterministic_only"
                    experiment.limits = limits
                    try:
                        from backend_api.services.log_service import LogService

                        LogService.error(
                            "llm.advisor",
                            f"LLM pivot failed for test case #{case.id}; deterministic decision retained",
                            detail=str(pivot_error),
                            experiment_id=case.experiment_id,
                            target_id=experiment.target_id,
                            data={
                                "event_type": "llm_pivot_failed",
                                "model": settings.LLM_MODEL,
                                "trigger_test_case_id": case.id,
                                "fallback": "deterministic_campaign_brain",
                            },
                            db=db,
                        )
                    except Exception:
                        pass
                    logger.warning("Mid-scan LLM pivot failed; deterministic pivot retained: %s", pivot_error)
            else:
                llm_pivot = None
        elif not hit:
            llm_pivot = None
            group_history = cls._history(db, case.experiment_id).get(cls._group_key(case), {})
            tried = len(group_history.get("techniques") or {})
            action = "deprioritize_repetition"
            rationale = "no execution or sink signal; reduce repeats while keeping alternatives alive"
            penalty = min(15, 4 + int(group_history.get("attempts", 1)))
            for sibling in siblings:
                if (sibling.technique or "unclassified") == technique:
                    sibling.priority -= penalty
                    adjusted += 1
            if tried >= 3 and not group_history.get("signals"):
                action = "saturate_context_without_claiming_safe"
                rationale = (
                    "three independent techniques produced no signal; heavily deprioritize this "
                    "context, but do not call it safe without proof"
                )
                for sibling in siblings:
                    sibling.priority -= 20
                    adjusted += 1

        event = {
            "at": datetime.now(UTC).isoformat(),
            "test_case_id": case.id,
            "endpoint_id": case.endpoint_id,
            "param_id": case.param_id,
            "context_id": case.context_id,
            "technique": technique,
            "outcome": "confirmed" if hit else ("signal" if signal else "negative"),
            "action": action,
            "rationale": rationale,
            "pending_priorities_adjusted": adjusted,
        }
        if llm_pivot:
            event["llm_pivot"] = llm_pivot
        limits = dict(experiment.limits or {})
        memory = dict(limits.get("campaign_brain") or {})
        counts = dict(memory.get("outcomes") or {})
        counts[event["outcome"]] = int(counts.get(event["outcome"], 0)) + 1
        trace = list(memory.get("decision_trace") or [])
        trace.append(event)
        memory.update({
            "model": cls.MODEL_VERSION,
            "outcomes": counts,
            "decision_trace": trace[-cls.MAX_TRACE:],
            "last_observation": event,
        })
        limits["campaign_brain"] = memory
        experiment.limits = limits
        db.commit()
        return event

    @classmethod
    def completion_reason(cls, db: Session, experiment_id: int) -> Optional[str]:
        """Return a truthful stop reason; absence of a finding is never called safe."""
        experiment = db.query(Experiment).filter(Experiment.id == experiment_id).first()
        if experiment is None:
            return "experiment_missing"
        limits = experiment.limits if isinstance(experiment.limits, dict) else {}
        if list(limits.get("human_interventions") or []):
            if any(item.get("status") == "open" for item in limits["human_interventions"] if isinstance(item, dict)):
                return "awaiting_human_intervention"
        remaining = db.query(TestCase).filter(
            TestCase.experiment_id == experiment_id,
            TestCase.status.in_([
                TestCaseStatus.PENDING, TestCaseStatus.QUEUED, TestCaseStatus.RUNNING,
            ]),
        ).count()
        if remaining:
            return None
        coverage = limits.get("coverage") if isinstance(limits.get("coverage"), dict) else {}
        if coverage.get("budget_exhausted"):
            return "budget_exhausted_with_unknowns"
        return "all_planned_evidence_collected"
