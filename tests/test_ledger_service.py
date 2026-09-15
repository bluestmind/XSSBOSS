"""LedgerService — build the coverage verdict from an experiment's persisted results."""
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend_api.models.base import BaseModel
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.models.execution import Execution, OracleStatus
from backend_api.services.ledger_service import LedgerService


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    BaseModel.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _tc(db, token, param_id, context_id):
    tc = TestCase(experiment_id=1, endpoint_id=1, param_id=param_id, context_id=context_id,
                  payload="p", token=token, status=TestCaseStatus.COMPLETED)
    db.add(tc)
    db.commit()
    return tc


def _exec(db, tc_id, status):
    db.add(Execution(test_case_id=tc_id, oracle_status=status, executed_at=datetime.now(UTC)))
    db.commit()


def test_coverage_classifies_confirmed_inconclusive_unreached(db):
    # (p1,c10): a HIT among 3 payloads -> CONFIRMED
    for i in range(3):
        tc = _tc(db, f"a{i}", 1, 10)
        _exec(db, tc.id, OracleStatus.HIT if i == 0 else OracleStatus.MISSED)
    # (p2,c20): fired but all MISSED -> INCONCLUSIVE
    for i in range(2):
        tc = _tc(db, f"b{i}", 2, 20)
        _exec(db, tc.id, OracleStatus.MISSED)
    # (p3,c30): a payload created but never executed -> UNREACHED
    _tc(db, "c0", 3, 30)

    cov = LedgerService.coverage_for_experiment(db, 1)
    counts = cov["coverage"]["counts"]
    assert counts["confirmed_vuln"] == 1
    assert counts["inconclusive"] == 1
    assert counts["unreached"] == 1
    assert cov["coverage"]["confirmed_vulnerabilities"] == 1
    # 1 decided of 3 -> won't claim clean, and surfaces the 2 gaps.
    assert cov["coverage"]["decided_fraction"] == round(1 / 3, 4)
    assert cov["trustworthy_clean"] is False
    assert len(cov["gaps"]) == 2


def test_empty_experiment_is_safe(db):
    cov = LedgerService.coverage_for_experiment(db, 999)
    assert cov["coverage"]["total"] == 0
    assert cov["gaps"] == []
