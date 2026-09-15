"""Behavioral tests for the evidence-driven campaign control loop."""
import json
from datetime import UTC, datetime
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import backend_api.models  # noqa: F401
from backend_api.models.base import BaseModel
from backend_api.models.context import Context
from backend_api.models.endpoint import Endpoint
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.models.log_event import LogEvent
from backend_api.models.param import Param
from backend_api.models.target import Target
from backend_api.models.tenant import Tenant
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.services.smart_campaign_brain import SmartCampaignBrain
from backend_api.config import settings


def _world():
    engine = create_engine("sqlite:///:memory:")
    BaseModel.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    tenant = Tenant(slug="brain", name="Brain")
    db.add(tenant)
    db.flush()
    target = Target(tenant_id=tenant.id, name="app", base_url="https://app.test")
    db.add(target)
    db.flush()
    endpoint = Endpoint(target_id=target.id, method="GET", url_pattern="https://app.test/search")
    db.add(endpoint)
    db.flush()
    p1 = Param(endpoint_id=endpoint.id, name="q", location="query")
    p2 = Param(endpoint_id=endpoint.id, name="next", location="query")
    db.add_all([p1, p2])
    db.flush()
    c1 = Context(endpoint_id=endpoint.id, param_id=p1.id, context_type="HTML_TEXT")
    c2 = Context(endpoint_id=endpoint.id, param_id=p2.id, context_type="URL_QUERY")
    db.add_all([c1, c2])
    db.flush()
    experiment = Experiment(
        target_id=target.id,
        name="smart run",
        strategy=ExperimentStrategy.SMART_ADAPTIVE,
        status=ExperimentStatus.RUNNING,
        limits={"autonomous_research": True},
    )
    db.add(experiment)
    db.commit()
    return db, experiment, endpoint, p1, p2, c1, c2


def _case(db, experiment, endpoint, param, context, token, priority, technique):
    row = TestCase(
        experiment_id=experiment.id,
        endpoint_id=endpoint.id,
        param_id=param.id,
        context_id=context.id,
        payload=f"probe-{token}",
        token=token,
        priority=priority,
        technique=technique,
        status=TestCaseStatus.PENDING,
    )
    db.add(row)
    db.flush()
    return row


def test_batch_selection_diversifies_parameters_and_explains_itself():
    db, experiment, endpoint, p1, p2, c1, c2 = _world()
    q1 = _case(db, experiment, endpoint, p1, c1, "q1", 100, "svg-event")
    q2 = _case(db, experiment, endpoint, p1, c1, "q2", 99, "event-handler")
    nxt = _case(db, experiment, endpoint, p2, c2, "n1", 98, "javascript-uri")
    db.commit()

    selected = SmartCampaignBrain.select_batch(db, experiment, [q1, q2, nxt], 2)

    assert q1 in selected
    assert nxt in selected
    assert q2 not in selected
    assert selected[0].research_metadata["brain"]["reasons"]
    assert experiment.limits["campaign_brain"]["model"] == "utility-loop-v2-llm-pivot"


def test_partial_sink_signal_pivots_to_a_different_technique():
    db, experiment, endpoint, p1, _p2, c1, _c2 = _world()
    fired = _case(db, experiment, endpoint, p1, c1, "fired", 100, "svg-event")
    same = _case(db, experiment, endpoint, p1, c1, "same", 80, "svg-event")
    alternate = _case(db, experiment, endpoint, p1, c1, "alt", 80, "event-handler")
    fired.status = TestCaseStatus.COMPLETED
    execution = Execution(
        test_case_id=fired.id,
        oracle_status=OracleStatus.MISSED,
        logs='{"sink":"Element.innerHTML"}',
        executed_at=datetime.now(UTC),
    )
    db.add(execution)
    db.commit()

    event = SmartCampaignBrain.observe(
        db, execution, {"logs": {"sink": "Element.innerHTML"}}
    )

    assert event["action"] == "pivot_on_partial_signal"
    assert alternate.priority == 92
    assert same.priority == 76
    assert alternate.status == TestCaseStatus.PENDING
    assert experiment.limits["campaign_brain"]["outcomes"]["signal"] == 1


def test_midscan_llm_pivot_selects_only_pending_candidate_and_is_cached():
    db, experiment, endpoint, p1, _p2, c1, _c2 = _world()
    fired = _case(db, experiment, endpoint, p1, c1, "fired-llm", 100, "svg-event")
    alternate = _case(db, experiment, endpoint, p1, c1, "alt-llm", 80, "event-handler")
    other = _case(db, experiment, endpoint, p1, c1, "other-llm", 81, "unicode-escape")
    fired.status = TestCaseStatus.COMPLETED
    execution = Execution(
        test_case_id=fired.id,
        oracle_status=OracleStatus.MISSED,
        logs='{"sink":"Element.innerHTML"}',
        executed_at=datetime.now(UTC),
    )
    db.add(execution)
    db.commit()

    recommendation = {
        "selected_candidate_id": alternate.id,
        "technique": "event-handler",
        "priority_boost": 17,
        "confidence": 0.82,
        "rationale": "different parser boundary",
    }
    raw_secret = "LLM-PIVOT-RAW-LINEAGE-SECRET"
    runtime_logs = {
        "sink": "Element.innerHTML",
        "errors": [{
            "runtime_lineage": {
                "classification": "value_influence",
                "raw_value": raw_secret,
            },
        }],
    }
    with (
        patch.object(settings, "LLM_MIDSCAN_MAX_CALLS", 12),
        patch("backend_api.services.llm_service.LLMService.advise_pivot", return_value=recommendation) as advisor,
    ):
        first = SmartCampaignBrain._apply_llm_pivot(
            db, execution, {"logs": runtime_logs}, [alternate, other]
        )
        second = SmartCampaignBrain._apply_llm_pivot(
            db, execution, {"logs": runtime_logs}, [alternate, other]
        )

    assert first["applied"] is True
    assert alternate.priority == 97
    assert other.priority == 81
    assert alternate.research_metadata["llm_pivot"]["trigger_test_case_id"] == fired.id
    assert second["cached"] is True
    assert second["applied"] is False
    assert alternate.priority == 97
    advisor.assert_called_once()
    advisor_evidence = advisor.call_args.args[0]
    assert raw_secret not in json.dumps(advisor_evidence)
    persisted_request = db.query(LogEvent).filter_by(
        module="llm.advisor",
        message=f"Requesting bounded LLM pivot advice for test case #{fired.id}",
    ).one()
    assert raw_secret not in json.dumps(persisted_request.data)


def test_three_negative_techniques_deprioritize_but_never_claim_safe():
    db, experiment, endpoint, p1, _p2, c1, _c2 = _world()
    executions = []
    for index, technique in enumerate(("svg-event", "event-handler", "script-element")):
        fired = _case(db, experiment, endpoint, p1, c1, f"miss-{index}", 100, technique)
        fired.status = TestCaseStatus.COMPLETED
        execution = Execution(
            test_case_id=fired.id,
            oracle_status=OracleStatus.MISSED,
            logs="{}",
            executed_at=datetime.now(UTC),
        )
        db.add(execution)
        executions.append(execution)
    remaining = _case(db, experiment, endpoint, p1, c1, "remaining", 90, "unicode-escape")
    db.commit()

    event = SmartCampaignBrain.observe(db, executions[-1], {"logs": {}})

    assert event["action"] == "saturate_context_without_claiming_safe"
    assert remaining.status == TestCaseStatus.PENDING
    assert remaining.priority == 70
    assert "do not call it safe" in event["rationale"]


def test_budget_completion_is_reported_as_unknown_not_safe():
    db, experiment, _endpoint, _p1, _p2, _c1, _c2 = _world()
    experiment.limits = {
        "autonomous_research": True,
        "coverage": {"budget_exhausted": True, "complete": False},
    }
    db.commit()

    assert SmartCampaignBrain.completion_reason(db, experiment.id) == "budget_exhausted_with_unknowns"
