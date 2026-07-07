"""Production scale and crash-recovery acceptance gate.

Requires PostgreSQL and Redis. It creates 100 durable runs and 10,000 queued
cases, kills API/orchestration/execution processes during active work, severs
Redis client connections, restarts all processes, and verifies terminal state
with no lost work or duplicate completed executions.
"""
import argparse
from collections import Counter
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _start_process(command: list[str], log_handle, env: dict[str, str]) -> subprocess.Popen:
    return subprocess.Popen(
        command,
        cwd=ROOT,
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )


def _stop_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.kill()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.terminate()
        process.wait(timeout=15)


def _wait_http(url: str, timeout: int) -> None:
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status < 500:
                    return
        except Exception as error:
            last_error = error
        time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for {url}: {last_error}")


def _wait_worker(app, expected_name: str, timeout: int) -> None:
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            replies = app.control.inspect(timeout=1).ping() or {}
            if any(expected_name in name for name in replies):
                return
        except Exception as error:
            # A connection-kill drill is expected to invalidate a socket that
            # may already be inside drain_events. Kombu reconnects on the next
            # control request; the gate must tolerate that one transient read.
            last_error = error
        time.sleep(0.5)
    raise RuntimeError(f"Celery worker {expected_name} did not become ready: {last_error}")


def _seed(db, run_count: int, case_count: int, gate_id: str) -> tuple[list[int], list[int]]:
    from backend_api.models.endpoint import Endpoint
    from backend_api.models.experiment import Experiment, ExperimentStatus, ExperimentStrategy
    from backend_api.models.param import Param
    from backend_api.models.run_state import RunStageName
    from backend_api.models.target import Target, TargetStatus
    from backend_api.models.test_case import TestCase, TestCaseStatus
    from backend_api.services.run_state_service import RunStateService

    target = Target(
        name=f"scale-gate-{gate_id}",
        base_url="https://scale-gate.invalid",
        status=TargetStatus.FUZZING,
        scope_tags={"allowed_hosts": ["scale-gate.invalid"], "acceptance_gate": True},
    )
    db.add(target)
    db.flush()
    endpoint = Endpoint(
        target_id=target.id,
        method="GET",
        url_pattern="https://scale-gate.invalid/?q=",
    )
    db.add(endpoint)
    db.flush()
    param = Param(endpoint_id=endpoint.id, name="q", location="query")
    db.add(param)
    db.flush()

    experiments = [
        Experiment(
            target_id=target.id,
            name=f"scale-gate-{gate_id}-{index:03d}",
            strategy=ExperimentStrategy.QUICK_LIGHT,
            status=ExperimentStatus.RUNNING,
            limits={"scale_gate": gate_id},
            started_at=datetime.now(UTC),
        )
        for index in range(run_count)
    ]
    db.add_all(experiments)
    db.commit()
    experiment_ids = [experiment.id for experiment in experiments]

    for experiment_id in experiment_ids:
        RunStateService.ensure_pipeline(db, experiment_id)
        RunStateService.add_endpoints(db, experiment_id, [endpoint.id], "scale-gate")
        for stage in (RunStageName.RECON, RunStageName.PROFILING):
            RunStateService.claim_stage(db, experiment_id, stage, "scale-gate")
            RunStateService.complete_stage(db, experiment_id, stage, {"synthetic": True})
        RunStateService.claim_stage(db, experiment_id, RunStageName.EXECUTION, "scale-gate")

    mappings = []
    for index in range(case_count):
        mappings.append({
            "experiment_id": experiment_ids[index % run_count],
            "endpoint_id": endpoint.id,
            "param_id": param.id,
            "payload": f"scale-probe-{index}",
            "token": f"scale-{gate_id[:12]}-{index}",
            "priority": 0,
            "status": TestCaseStatus.QUEUED,
            "attempt_count": 0,
        })
    db.bulk_insert_mappings(TestCase, mappings)
    db.commit()
    test_case_ids = [
        row[0]
        for row in (
            db.query(TestCase.id)
            .filter(TestCase.experiment_id.in_(experiment_ids))
            .order_by(TestCase.id)
            .all()
        )
    ]
    return experiment_ids, test_case_ids


def _finish_runs(db, experiment_ids: list[int]) -> None:
    from backend_api.models.experiment import Experiment, ExperimentStatus
    from backend_api.models.run_state import RunStageName
    from backend_api.services.run_state_service import RunStateService

    for experiment_id in experiment_ids:
        RunStateService.complete_stage(db, experiment_id, RunStageName.EXECUTION)
        for stage in (RunStageName.CORRELATION, RunStageName.REPORTING):
            RunStateService.claim_stage(db, experiment_id, stage, "scale-gate")
            RunStateService.complete_stage(db, experiment_id, stage, {"synthetic": True})
    db.query(Experiment).filter(Experiment.id.in_(experiment_ids)).update(
        {Experiment.status: ExperimentStatus.COMPLETED, Experiment.completed_at: datetime.now(UTC)},
        synchronize_session=False,
    )
    db.commit()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the 100-run/10,000-case recovery gate")
    parser.add_argument("--runs", type=int, default=100)
    parser.add_argument("--cases", type=int, default=10_000)
    parser.add_argument("--worker-concurrency", type=int, default=16)
    parser.add_argument("--worker-replicas", type=int, default=4)
    parser.add_argument("--execution-delay-ms", type=int, default=50)
    parser.add_argument("--message-batch-size", type=int, default=16)
    parser.add_argument("--visibility-timeout", type=int, default=30)
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument("--p95-queue-delay-seconds", type=float, default=180.0)
    parser.add_argument("--max-completion-seconds", type=float, default=600.0)
    parser.add_argument("--api-port", type=int, default=8123)
    parser.add_argument("--artifact", type=Path, default=ROOT / "reports" / "scale_recovery.json")
    args = parser.parse_args()

    if args.runs < 100 or args.cases < 10_000:
        raise SystemExit("The release gate requires at least 100 runs and 10,000 cases")
    minimum_visibility = max(30, int(args.cases * 0.001) + 15)
    if args.visibility_timeout < minimum_visibility:
        raise SystemExit(
            f"visibility timeout must be at least {minimum_visibility}s for {args.cases} fan-out messages"
        )

    os.environ["CELERY_VISIBILITY_TIMEOUT"] = str(args.visibility_timeout)
    os.environ["BROWSER_LEASE_SECONDS"] = str(args.visibility_timeout)
    os.environ["ORCHESTRATION_MODE"] = "celery"
    os.environ["CELERY_TASK_ALWAYS_EAGER"] = "False"
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("PYTHONPATH", str(ROOT))

    from redis import Redis
    from sqlalchemy import func

    from backend_api.config import settings
    if not settings.DATABASE_URL.startswith(("postgresql://", "postgresql+psycopg://")):
        raise SystemExit("Scale recovery gate requires PostgreSQL")
    if not settings.REDIS_URL.startswith(("redis://", "rediss://")):
        raise SystemExit("Scale recovery gate requires Redis")

    from backend_api.db.base import SessionLocal, init_db
    from backend_api.models.execution import Execution
    from backend_api.models.experiment import Experiment, ExperimentStatus
    from backend_api.models.run_state import RunStage, RunStageStatus
    from backend_api.models.test_case import TestCase, TestCaseStatus
    from backend_api.task_queue import task_app

    redis_client = Redis.from_url(settings.REDIS_URL)
    redis_client.ping()
    init_db()
    gate_id = uuid.uuid4().hex
    report = {
        "schema_version": 1,
        "gate_id": gate_id,
        "requested_runs": args.runs,
        "requested_cases": args.cases,
        "started_at": datetime.now(UTC).isoformat(),
        "passed": False,
    }
    args.artifact.parent.mkdir(parents=True, exist_ok=True)
    worker_log_path = args.artifact.with_suffix(".workers.log")
    env = os.environ.copy()
    processes: list[subprocess.Popen] = []
    db = SessionLocal()
    started = time.monotonic()

    def start_worker(queue: str, name: str, concurrency: int) -> subprocess.Popen:
        command = [
            sys.executable, "-m", "celery", "-A", "backend_api.task_queue:task_app",
            "worker", "-Q", queue, "--pool=threads", f"--concurrency={concurrency}",
            "--loglevel=WARNING", "--without-gossip", "--without-mingle", "-n", f"{name}@%h",
        ]
        process = _start_process(command, worker_log, env)
        processes.append(process)
        return process

    def start_api() -> subprocess.Popen:
        command = [
            sys.executable, "-m", "uvicorn", "backend_api.main:app",
            "--host", "127.0.0.1", "--port", str(args.api_port), "--log-level", "warning",
        ]
        process = _start_process(command, worker_log, env)
        processes.append(process)
        return process

    try:
        with worker_log_path.open("w", encoding="utf-8") as worker_log:
            experiment_ids, test_case_ids = _seed(db, args.runs, args.cases, gate_id)
            report["experiment_ids"] = experiment_ids

            execution_workers = [
                start_worker("recovery", f"scale-execution-{index}", args.worker_concurrency)
                for index in range(args.worker_replicas)
            ]
            orchestrator = start_worker("orchestration-scale", "scale-orchestrator", 1)
            api = start_api()
            for index in range(args.worker_replicas):
                _wait_worker(task_app, f"scale-execution-{index}", 60)
            _wait_worker(task_app, "scale-orchestrator", 60)
            _wait_http(f"http://127.0.0.1:{args.api_port}/ready", 60)

            task_app.send_task(
                "scale_fanout",
                args=[
                    gate_id,
                    experiment_ids,
                    args.execution_delay_ms,
                    0,
                    args.message_batch_size,
                ],
                queue="orchestration-scale",
                ignore_result=True,
            )

            disruption_deadline = time.monotonic() + 60
            running_before_kill = 0
            fanout_depth = 0
            while time.monotonic() < disruption_deadline:
                db.expire_all()
                running_before_kill = db.query(TestCase).filter(
                    TestCase.id.in_(test_case_ids), TestCase.status == TestCaseStatus.RUNNING
                ).count()
                fanout_depth = redis_client.llen("recovery")
                if running_before_kill > 0 and fanout_depth >= 50:
                    break
                time.sleep(0.25)
            if running_before_kill == 0 or fanout_depth < 50:
                raise RuntimeError("Could not reach active-work disruption point")

            _stop_process(api)
            _stop_process(orchestrator)
            for execution_worker in execution_workers:
                _stop_process(execution_worker)
            disrupted_at = time.monotonic()
            report["disruption"] = {
                "api_killed": True,
                "orchestrator_killed": True,
                "execution_workers_killed": len(execution_workers),
                "running_cases_at_kill": running_before_kill,
                "queued_cases_at_kill": fanout_depth,
            }

            # Sever all other normal clients; replacement processes must reconnect.
            killed_connections = redis_client.execute_command(
                "CLIENT", "KILL", "TYPE", "normal", "SKIPME", "yes"
            )
            report["disruption"]["redis_connections_killed"] = int(killed_connections)

            # The controller deliberately killed its Celery publisher/control
            # sockets too. Drop cached Kombu/backend pools so subsequent health
            # checks establish new TCP connections instead of reusing a severed
            # descriptor.
            from celery import Celery

            prior_task_app = task_app
            try:
                prior_task_app.backend.client.connection_pool.disconnect()
            except Exception:
                pass
            prior_task_app.close()
            task_app = Celery(
                "xssboss-scale-controller-reconnected",
                broker=settings.REDIS_URL,
                backend=settings.REDIS_URL,
            )
            task_app.conf.update(prior_task_app.conf)
            redis_client.connection_pool.disconnect()
            redis_client = Redis.from_url(settings.REDIS_URL)
            redis_client.ping()

            execution_workers = [
                start_worker("recovery", f"scale-execution-replacement-{index}", args.worker_concurrency)
                for index in range(args.worker_replicas)
            ]
            orchestrator = start_worker("orchestration-scale", "scale-orchestrator-replacement", 1)
            api = start_api()
            for index in range(args.worker_replicas):
                _wait_worker(task_app, f"scale-execution-replacement-{index}", 60)
            _wait_worker(task_app, "scale-orchestrator-replacement", 60)
            _wait_http(f"http://127.0.0.1:{args.api_port}/ready", 60)

            # Redis transports may retain reserved late-acked messages longer
            # than their advertised visibility window. Reconcile from the
            # authoritative database after leases expire; a later broker
            # redelivery is absorbed by per-case idempotency.
            recovery_wait = max(
                0.0,
                args.visibility_timeout + 1.0 - (time.monotonic() - disrupted_at),
            )
            if recovery_wait:
                time.sleep(recovery_wait)
            task_app.send_task(
                "scale_recover",
                args=[experiment_ids, args.execution_delay_ms, args.message_batch_size],
                queue="orchestration-scale",
                ignore_result=True,
            )
            report["disruption"]["database_reconciliation_dispatched"] = True

            deadline = time.monotonic() + args.timeout
            completed = 0
            while time.monotonic() < deadline:
                db.expire_all()
                completed = db.query(TestCase).filter(
                    TestCase.id.in_(test_case_ids), TestCase.status == TestCaseStatus.COMPLETED
                ).count()
                if completed == args.cases:
                    break
                time.sleep(1)
            if completed != args.cases:
                raise RuntimeError(f"Only {completed}/{args.cases} cases completed before timeout")

            # Replay a deterministic subset after completion to prove immutable
            # completed state under late duplicate delivery.
            with task_app.producer_or_acquire() as producer:
                for test_case_id in test_case_ids[:1000]:
                    task_app.send_task(
                        "scale_probe", args=[test_case_id, 0], queue="recovery",
                        producer=producer, ignore_result=True,
                    )
            duplicate_deadline = time.monotonic() + 60
            while time.monotonic() < duplicate_deadline and redis_client.llen("recovery"):
                time.sleep(0.5)
            time.sleep(2)

            _finish_runs(db, experiment_ids)
            db.expire_all()
            # Seed a representative, portable evidence bundle so the following
            # backup/restore job verifies database metadata and separately
            # restored evidence bytes together.
            from backend_api.services.evidence_service import EvidenceService

            proof_execution = db.query(Execution).filter(
                Execution.test_case_id.in_(test_case_ids)
            ).order_by(Execution.id).first()
            proof_execution.dom_snapshot = "<html><body>scale-recovery-proof</body></html>"
            db.commit()
            EvidenceService.register_execution(
                db,
                proof_execution,
                request_data={
                    "method": "GET",
                    "url": "https://scale-gate.invalid/?q=restore-proof",
                    "headers": {"Authorization": "acceptance-secret"},
                },
                result={
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "final_url": "https://scale-gate.invalid/?q=restore-proof",
                    "oracle_hit": False,
                },
            )
            evidence_verification = EvidenceService.verify_all(db)
            status_counts = Counter({
                str(status): count
                for status, count in (
                    db.query(TestCase.status, func.count(TestCase.id))
                    .filter(TestCase.id.in_(test_case_ids))
                    .group_by(TestCase.status)
                    .all()
                )
            })
            execution_count = db.query(Execution).filter(
                Execution.test_case_id.in_(test_case_ids)
            ).count()
            duplicate_execution_groups = (
                db.query(Execution.test_case_id)
                .filter(Execution.test_case_id.in_(test_case_ids))
                .group_by(Execution.test_case_id)
                .having(func.count(Execution.id) > 1)
                .count()
            )
            recovered_cases = db.query(TestCase).filter(
                TestCase.id.in_(test_case_ids), TestCase.attempt_count > 1
            ).count()
            terminal_runs = db.query(Experiment).filter(
                Experiment.id.in_(experiment_ids), Experiment.status == ExperimentStatus.COMPLETED
            ).count()
            completed_stages = db.query(RunStage).filter(
                RunStage.experiment_id.in_(experiment_ids), RunStage.status == RunStageStatus.COMPLETED
            ).count()
            fanout_deliveries = int(redis_client.get(
                f"xssboss:scale:{gate_id}:fanout_deliveries"
            ) or 0)
            queue_delays = sorted(
                max(0.0, (first_claimed_at - created_at).total_seconds())
                for first_claimed_at, created_at in db.query(
                    TestCase.first_claimed_at, TestCase.created_at
                ).filter(TestCase.id.in_(test_case_ids)).all()
                if first_claimed_at is not None
            )
            queue_delay_p95 = queue_delays[int(0.95 * (len(queue_delays) - 1))] if queue_delays else float("inf")
            total_duration = time.monotonic() - started

            report.update({
                "completed_cases": completed,
                "execution_count": execution_count,
                "duplicate_execution_groups": duplicate_execution_groups,
                "recovered_cases": recovered_cases,
                "terminal_runs": terminal_runs,
                "completed_stages": completed_stages,
                "fanout_deliveries": fanout_deliveries,
                "evidence": {
                    "total": evidence_verification["total"],
                    "valid": evidence_verification["valid"],
                    "invalid": evidence_verification["invalid"],
                    "passed": evidence_verification["passed"],
                },
                "status_counts": dict(status_counts),
                "slos": {
                    "queue_delay_p95_seconds": round(queue_delay_p95, 3),
                    "queue_delay_budget_seconds": args.p95_queue_delay_seconds,
                    "completion_seconds": round(total_duration, 3),
                    "completion_budget_seconds": args.max_completion_seconds,
                },
                "duration_seconds": round(total_duration, 3),
            })
            report["passed"] = all([
                completed == args.cases,
                execution_count == args.cases,
                duplicate_execution_groups == 0,
                recovered_cases > 0,
                terminal_runs == args.runs,
                completed_stages == args.runs * 5,
                fanout_deliveries >= 2,
                report["disruption"]["redis_connections_killed"] > 0,
                evidence_verification["passed"],
                len(queue_delays) == args.cases,
                queue_delay_p95 <= args.p95_queue_delay_seconds,
                total_duration <= args.max_completion_seconds,
            ])
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
        report["traceback"] = traceback.format_exc()
    finally:
        for process in reversed(processes):
            _stop_process(process)
        db.close()
        report["finished_at"] = datetime.now(UTC).isoformat()
        args.artifact.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
