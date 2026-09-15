"""Unified Oracle contract: rejection, taint-vs-execution, atomic single-consume.

Guards the behaviors that were previously split across two half-complete implementations:
* the standalone oracle now rejects replays / already-consumed tokens (it did not before);
* the API router now distinguishes taint from execution (it marked every callback a HIT before).
"""
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend_api.models.base import BaseModel
from backend_api.models.test_case import TestCase
from backend_api.models.execution import Execution, OracleStatus
from backend_api.services.oracle_service import process_oracle_callback


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    BaseModel.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _make_tc(db, token="tok-123", **kw):
    tc = TestCase(experiment_id=1, endpoint_id=1, param_id=1,
                  payload="<script>alert(1)</script>", token=token, **kw)
    db.add(tc)
    db.commit()
    return tc


# --------------------------------------------------------------- rejection

def test_unknown_token_404(db):
    with pytest.raises(HTTPException) as ei:
        process_oracle_callback(db, "nope")
    assert ei.value.status_code == 404


def test_expired_token_410(db):
    _make_tc(db, token="exp", token_expires_at=datetime.now(UTC) - timedelta(hours=1))
    with pytest.raises(HTTPException) as ei:
        process_oracle_callback(db, "exp", kind="execution")
    assert ei.value.status_code == 410


def test_preconsumed_token_410(db):
    _make_tc(db, token="used", token_consumed_at=datetime.now(UTC))
    with pytest.raises(HTTPException) as ei:
        process_oracle_callback(db, "used", kind="execution")
    assert ei.value.status_code == 410


# --------------------------------------------------- execution & single-consume

def test_execution_marks_hit_and_consumes(db):
    tc = _make_tc(db, token="exec1")
    res = process_oracle_callback(db, "exec1", kind="execution", sink="eval")
    assert res["is_execution"] is True
    db.refresh(tc)
    assert tc.token_consumed_at is not None  # consumed
    ex = db.query(Execution).filter(Execution.test_case_id == tc.id).first()
    assert ex.oracle_status == OracleStatus.HIT


def test_replay_after_execution_is_rejected(db):
    """The bug this whole change targets: a second execution callback must not re-fire."""
    _make_tc(db, token="exec2")
    process_oracle_callback(db, "exec2", kind="execution", sink="eval")
    with pytest.raises(HTTPException) as ei:
        process_oracle_callback(db, "exec2", kind="execution", sink="eval")
    assert ei.value.status_code == 410


# ------------------------------------------------------ taint does not consume

def test_taint_records_telemetry_without_consuming(db):
    tc = _make_tc(db, token="taint1")
    res = process_oracle_callback(db, "taint1", kind="taint", sink="innerHTML")
    assert res["is_execution"] is False
    db.refresh(tc)
    assert tc.token_consumed_at is None  # NOT consumed
    ex = db.query(Execution).filter(Execution.test_case_id == tc.id).first()
    assert ex.oracle_status == OracleStatus.MISSED


def test_taint_then_execution_still_confirms(db):
    tc = _make_tc(db, token="mix1")
    process_oracle_callback(db, "mix1", kind="taint", sink="innerHTML")   # telemetry
    res = process_oracle_callback(db, "mix1", kind="execution", sink="eval")  # real hit
    assert res["is_execution"] is True
    db.refresh(tc)
    assert tc.token_consumed_at is not None
    ex = db.query(Execution).filter(Execution.test_case_id == tc.id).order_by(Execution.executed_at.desc()).first()
    assert ex.oracle_status == OracleStatus.HIT


# ---------------------------------------------------- router regression guard

def test_router_taint_is_not_a_hit(db):
    """The API router previously marked EVERY callback HIT; a taint callback must now MISS."""
    from backend_api.routers.oracle import oracle_callback as router_cb

    tc = _make_tc(db, token="rtr1")
    res = router_cb(token="rtr1", msg=None, sink="innerHTML", kind="taint", data=None, db=db)
    assert res["is_execution"] is False
    assert res["finding_id"] is None
    db.refresh(tc)
    assert tc.token_consumed_at is None


def test_atomic_consume_guard_via_direct_update(db):
    """Simulate a concurrent winner: pre-consume, then the execution callback loses the race."""
    tc = _make_tc(db, token="race1")
    # Another worker consumes first.
    db.query(TestCase).filter(TestCase.id == tc.id).update({TestCase.token_consumed_at: datetime.now(UTC)})
    db.commit()
    with pytest.raises(HTTPException) as ei:
        process_oracle_callback(db, "race1", kind="execution", sink="eval")
    assert ei.value.status_code == 410
