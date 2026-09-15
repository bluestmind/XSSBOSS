from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import backend_api.models  # noqa: F401
from backend_api.models.base import BaseModel
from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
from backend_api.models.test_case import TestCase, TestCaseStatus
from backend_api.services.run_budget_service import RunBudgetService
from backend_api.services.test_case_lease_service import TestCaseLeaseService


def _db_with_cases(max_requests=2, count=3):
    engine = create_engine("sqlite:///:memory:")
    BaseModel.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    experiment = Experiment(
        target_id=1,
        name="bounded",
        strategy=ExperimentStrategy.SMART_ADAPTIVE,
        status=ExperimentStatus.RUNNING,
        limits={"max_requests": max_requests, "max_test_cases": count},
    )
    db.add(experiment)
    db.flush()
    cases = []
    for index in range(count):
        case = TestCase(
            experiment_id=experiment.id,
            endpoint_id=1,
            param_id=1,
            payload="p",
            token=f"budget-{index}",
            status=TestCaseStatus.PENDING,
        )
        db.add(case)
        cases.append(case)
    db.commit()
    return db, experiment, cases


def test_browser_leases_cannot_overspend_declared_request_cap():
    db, experiment, cases = _db_with_cases(max_requests=2)
    assert TestCaseLeaseService.claim_snapshot(db, cases[0].id, "one", 60)
    assert TestCaseLeaseService.claim_snapshot(db, cases[1].id, "two", 60)
    assert TestCaseLeaseService.claim_snapshot(db, cases[2].id, "three", 60) is None

    snapshot = RunBudgetService.snapshot(db, experiment.id)
    assert snapshot.request_attempts == 2
    assert snapshot.requests_remaining == 0
    assert db.get(TestCase, cases[2].id).status == TestCaseStatus.SKIPPED


def test_three_request_lineage_probe_requires_remaining_budget():
    db, experiment, cases = _db_with_cases(max_requests=3, count=1)
    cases[0].attempt_count = 1
    db.commit()
    assert RunBudgetService.reserve_runtime_lineage_probe(db, cases[0]) is False

    experiment.limits = {"max_requests": 4}
    db.commit()
    assert RunBudgetService.reserve_runtime_lineage_probe(db, cases[0]) is True
    snapshot = RunBudgetService.snapshot(db, experiment.id)
    assert snapshot.requests_reserved == 4
    assert snapshot.requests_remaining == 0


def test_program_scheduler_reserves_async_cap_but_reclaims_terminal_unused_budget():
    db, experiment, _ = _db_with_cases(max_requests=50, count=2)
    running = RunBudgetService.snapshot(db, experiment.id)
    assert RunBudgetService.program_allocation(running, ExperimentStatus.RUNNING, 50) == 50

    experiment.status = ExperimentStatus.COMPLETED
    db.commit()
    terminal = RunBudgetService.snapshot(db, experiment.id)
    assert RunBudgetService.program_allocation(terminal, experiment.status, 50) == 0
