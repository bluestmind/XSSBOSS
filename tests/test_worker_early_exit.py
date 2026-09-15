"""Early-exit: stop firing once a (param, context) is confirmed — the big winrate/time win."""
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend_api.models.base import BaseModel
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    BaseModel.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _tc(db, token, context_id):
    if db.get(Experiment, 1) is None:
        db.add(Experiment(
            id=1,
            target_id=1,
            name="worker-test",
            strategy=ExperimentStrategy.SMART_ADAPTIVE,
            status=ExperimentStatus.RUNNING,
            limits={},
        ))
        db.flush()
    tc = TestCase(experiment_id=1, endpoint_id=1, param_id=1, context_id=context_id,
                  payload="p", token=token, status=TestCaseStatus.PENDING)
    db.add(tc)
    db.commit()
    return tc


def test_confirmed_sibling_triggers_early_exit(db):
    from browser_workers.worker import context_already_confirmed

    tc1 = _tc(db, "t1", context_id=5)
    tc2 = _tc(db, "t2", context_id=5)   # same (param, context)
    tc3 = _tc(db, "t3", context_id=9)   # different context

    # Nothing confirmed yet → keep firing.
    assert context_already_confirmed(db, tc2) is False

    # tc1 confirms the bug.
    db.add(Execution(test_case_id=tc1.id, oracle_status=OracleStatus.HIT, executed_at=datetime.now(UTC)))
    db.commit()

    # Its siblings in the SAME context are now skipped (no wasted browser runs).
    assert context_already_confirmed(db, tc2) is True
    # The winner itself isn't skipped (no *other* case confirmed it).
    assert context_already_confirmed(db, tc1) is False
    # A DIFFERENT context is still tested — no winrate loss.
    assert context_already_confirmed(db, tc3) is False


def test_missed_execution_does_not_trigger_exit(db):
    from browser_workers.worker import context_already_confirmed

    tc1 = _tc(db, "m1", context_id=7)
    tc2 = _tc(db, "m2", context_id=7)
    db.add(Execution(test_case_id=tc1.id, oracle_status=OracleStatus.MISSED, executed_at=datetime.now(UTC)))
    db.commit()
    assert context_already_confirmed(db, tc2) is False   # a miss is not a confirmation


def test_no_context_never_exits(db):
    from browser_workers.worker import context_already_confirmed

    tc = _tc(db, "n1", context_id=None)
    assert context_already_confirmed(db, tc) is False


def test_reconcile_persisted_callback_hit(db):
    from browser_workers.worker import reconcile_persisted_oracle_hit

    tc = _tc(db, "callback-hit", context_id=None)
    db.add(Execution(test_case_id=tc.id, oracle_status=OracleStatus.HIT))
    db.commit()

    assert reconcile_persisted_oracle_hit(db, tc.id) is True


def test_reconcile_consumed_token_closes_callback_commit_window(db):
    from browser_workers.worker import reconcile_persisted_oracle_hit

    tc = _tc(db, "consumed-hit", context_id=None)
    tc.token_consumed_at = datetime.now(UTC)
    db.commit()

    assert reconcile_persisted_oracle_hit(db, tc.id) is True


def test_reconcile_unconsumed_miss_stays_negative(db):
    from browser_workers.worker import reconcile_persisted_oracle_hit

    tc = _tc(db, "real-miss", context_id=None)

    assert reconcile_persisted_oracle_hit(db, tc.id) is False


def test_runtime_lineage_probe_attempt_is_durably_reserved_once(db):
    from browser_workers.worker import claim_runtime_lineage_probe_attempt

    tc = _tc(db, "lineage-probe", context_id=None)
    tc.attempt_count = 2
    tc.research_metadata = {"runtime_lineage_aab": True, "preserved": "value"}
    db.commit()

    assert claim_runtime_lineage_probe_attempt(db, tc) is True

    db.expire_all()
    persisted = db.get(TestCase, tc.id)
    assert persisted.research_metadata == {
        "runtime_lineage_aab": True,
        "preserved": "value",
        "runtime_lineage_aab_attempt": {
            "schema_version": "runtime-lineage-probe-attempt/v1",
            "attempt_no": 2,
            "reserved_requests": 3,
        },
        "budget_request_reservations": {"runtime_lineage_aab": 3},
    }
    assert claim_runtime_lineage_probe_attempt(db, persisted) is False

    db.expire_all()
    assert db.get(TestCase, tc.id).research_metadata[
        "runtime_lineage_aab_attempt"
    ]["reserved_requests"] == 3
    assert db.get(TestCase, tc.id).runtime_lineage_probe_reserved_at is not None


def test_runtime_lineage_probe_reservation_is_atomic_across_stale_sessions(db):
    from browser_workers.worker import claim_runtime_lineage_probe_attempt

    tc = _tc(db, "lineage-probe-race", context_id=None)
    Session = sessionmaker(bind=db.get_bind())
    first_session = Session()
    second_session = Session()
    try:
        first = first_session.get(TestCase, tc.id)
        second = second_session.get(TestCase, tc.id)
        assert first is not None and second is not None

        assert claim_runtime_lineage_probe_attempt(first_session, first) is True
        assert claim_runtime_lineage_probe_attempt(second_session, second) is False
    finally:
        first_session.close()
        second_session.close()


def test_ineligible_runtime_lineage_primary_does_not_consume_durable_reservation(db):
    from browser_workers.worker import (
        claim_runtime_lineage_probe_attempt_if_eligible,
    )

    tc = _tc(db, "lineage-ineligible", context_id=None)
    tc.attempt_count = 1
    tc.research_metadata = {"runtime_lineage_aab": True}
    db.commit()
    test_case_data = {
        "test_case_id": tc.id,
        "method": "GET",
        "url": "https://authorized.invalid/search?q=original",
        "body": None,
        "json": None,
        "steps": None,
        "stored_view_url": None,
    }
    primary_result = {
        "oracle_hit": False,
        "execution_error": None,
        "human_intervention": None,
        "status_code": 200,
        "final_url": test_case_data["url"],
        "logs": {
            "runtime_lineage": {
                "causal_flows": [{
                    "classification": "causal_only",
                    "candidate_id": "a" * 64,
                    "sink_fingerprint": "b" * 64,
                    # An untyped category used to raise after the claim was
                    # already committed. It must now fail before reservation.
                    "source_category": [],
                    "sink_category": "innerhtml",
                }],
            },
        },
    }
    executor = SimpleNamespace(
        uc_driver=None,
        create_runtime_lineage_envelope=lambda data: {"version": 1},
    )

    assert claim_runtime_lineage_probe_attempt_if_eligible(
        db,
        tc,
        executor,
        test_case_data,
        primary_result,
        param_name="q",
        param_location="query",
    ) is False

    db.expire_all()
    persisted = db.get(TestCase, tc.id)
    assert persisted.research_metadata == {"runtime_lineage_aab": True}


@pytest.mark.parametrize("status_code", [403, 429])
def test_browser_rate_limit_signal_recognizes_waf_statuses(status_code):
    from browser_workers.worker import browser_rate_limit_signal

    assert browser_rate_limit_signal({"status_code": status_code}) == (True, None)


def test_browser_rate_limit_signal_clamps_retry_after_to_one_day():
    from browser_workers.worker import browser_rate_limit_signal

    assert browser_rate_limit_signal({
        "status_code": 429,
        "headers": {"retry-after": "999999"},
    }) == (True, 86_400.0)
    assert browser_rate_limit_signal({
        "status_code": 403,
        "headers": {"retry-after": "-12"},
    }) == (True, 0.0)
    assert browser_rate_limit_signal({
        "status_code": 429,
        "headers": {"retry-after": "not-seconds"},
    }) == (True, None)


def test_browser_rate_limit_signal_uses_bounded_error_markers_only():
    from browser_workers.worker import browser_rate_limit_signal

    assert browser_rate_limit_signal({
        "status_code": 200,
        "headers": {"retry-after": "120"},
        "logs": {"errors": ["upstream replied: Too Many Requests"]},
    }) == (True, None)
    assert browser_rate_limit_signal({
        "status_code": 500,
        "logs": {"errors": ["ordinary application error"]},
    }) == (False, None)
    assert browser_rate_limit_signal({
        "status_code": 200,
        "logs": {"errors": "429 supplied in an invalid container"},
    }) == (False, None)
