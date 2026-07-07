"""Durable task routing for horizontally scalable worker classes."""
from celery import Celery

from backend_api.config import settings


task_app = Celery("xssboss", broker=settings.REDIS_URL, backend=settings.REDIS_URL)
task_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    broker_transport_options={"visibility_timeout": settings.CELERY_VISIBILITY_TIMEOUT},
    task_routes={
        "scan_pipeline": {"queue": "orchestration"},
        "execute_test_case": {"queue": "browser"},
        "scale_probe": {"queue": "recovery"},
        "scale_probe_batch": {"queue": "recovery"},
        "scale_fanout": {"queue": "orchestration-scale"},
        "scale_recover": {"queue": "orchestration-scale"},
        "append_audit_event": {"queue": "audit"},
        "retention_sweep": {"queue": "maintenance"},
    },
    beat_schedule={
        "daily-tenant-retention": {
            "task": "retention_sweep",
            "schedule": 86400.0,
        },
    },
)


@task_app.task(name="scan_pipeline", bind=True, max_retries=5)
def scan_pipeline_task(self, payload: dict):
    """Resume the durable scan state machine after process loss."""
    from backend_api.routers.scans import _run_scan_task

    try:
        return _run_scan_task(**payload)
    except Exception as error:
        raise self.retry(exc=error, countdown=min(300, 2 ** self.request.retries * 10))


@task_app.task(
    name="scale_probe",
    bind=True,
    acks_late=True,
    reject_on_worker_lost=True,
    ignore_result=True,
)
def scale_probe_task(self, test_case_id: int, delay_ms: int = 25):
    """Synthetic execution used only by the production recovery gate.

    It exercises the same database lease and execution idempotency contract as
    browser work without launching ten thousand Chromium processes.
    """
    from backend_api.db.base import SessionLocal
    from backend_api.services.scale_probe_service import ScaleProbeService

    db = SessionLocal()
    try:
        owner = getattr(self.request, "hostname", None) or "scale-worker"
        return ScaleProbeService.process(db, test_case_id, owner, delay_ms)
    finally:
        db.close()


@task_app.task(
    name="scale_probe_batch",
    bind=True,
    acks_late=True,
    reject_on_worker_lost=True,
    ignore_result=True,
)
def scale_probe_batch_task(self, test_case_ids: list[int], delay_ms: int = 25):
    """Process a durable micro-batch while preserving per-case leases.

    If the worker dies, Celery redelivers the entire batch. Completed case IDs
    are immutable and skipped; the interrupted case is recovered by its lease.
    """
    from backend_api.db.base import SessionLocal
    from backend_api.services.scale_probe_service import ScaleProbeService

    db = SessionLocal()
    owner = getattr(self.request, "hostname", None) or "scale-worker"
    outcomes = {}
    try:
        for test_case_id in test_case_ids:
            result = ScaleProbeService.process(db, int(test_case_id), owner, delay_ms)
            outcomes[result["status"]] = outcomes.get(result["status"], 0) + 1
        return {"cases": len(test_case_ids), "outcomes": outcomes}
    finally:
        db.close()


@task_app.task(
    name="scale_fanout",
    bind=True,
    acks_late=True,
    reject_on_worker_lost=True,
    ignore_result=True,
)
def scale_fanout_task(
    self,
    gate_id: str,
    experiment_ids: list[int],
    execution_delay_ms: int = 25,
    fanout_pause_ms: int = 0,
    message_batch_size: int = 16,
):
    """Fan out a recoverable scale run.

    Redelivery deliberately replays already-published messages. The database
    execution lease must absorb those duplicates without duplicate completions.
    """
    import time

    from redis import Redis

    from backend_api.db.base import SessionLocal
    from backend_api.models.test_case import TestCase

    redis_client = Redis.from_url(settings.REDIS_URL)
    counter_key = f"xssboss:scale:{gate_id}:fanout_deliveries"
    redis_client.incr(counter_key)
    redis_client.expire(counter_key, 3600)

    db = SessionLocal()
    try:
        rows = (
            db.query(TestCase.id)
            .filter(TestCase.experiment_id.in_(experiment_ids))
            .order_by(TestCase.id)
            .yield_per(500)
        )
        sent = 0
        batch: list[int] = []
        batch_size = max(1, min(100, int(message_batch_size)))
        with task_app.producer_or_acquire() as producer:
            for (test_case_id,) in rows:
                batch.append(test_case_id)
                sent += 1
                if len(batch) >= batch_size:
                    task_app.send_task(
                        "scale_probe_batch",
                        args=[batch, execution_delay_ms],
                        queue="recovery",
                        producer=producer,
                        ignore_result=True,
                    )
                    batch = []
                if fanout_pause_ms > 0:
                    time.sleep(fanout_pause_ms / 1000)
            if batch:
                task_app.send_task(
                    "scale_probe_batch",
                    args=[batch, execution_delay_ms],
                    queue="recovery",
                    producer=producer,
                    ignore_result=True,
                )
        return {"sent": sent, "gate_id": gate_id, "message_batch_size": batch_size}
    finally:
        db.close()


@task_app.task(
    name="scale_recover",
    bind=True,
    acks_late=True,
    reject_on_worker_lost=True,
    ignore_result=True,
)
def scale_recover_task(
    self,
    experiment_ids: list[int],
    execution_delay_ms: int = 25,
    message_batch_size: int = 16,
):
    """Reconcile broker state from durable queued/expired database work."""
    from datetime import UTC, datetime

    from sqlalchemy import or_

    from backend_api.db.base import SessionLocal
    from backend_api.models.test_case import TestCase, TestCaseStatus

    db = SessionLocal()
    batch_size = max(1, min(100, int(message_batch_size)))
    try:
        rows = db.query(TestCase.id).filter(
            TestCase.experiment_id.in_(experiment_ids),
            or_(
                TestCase.status.in_([TestCaseStatus.PENDING, TestCaseStatus.QUEUED]),
                (
                    (TestCase.status == TestCaseStatus.RUNNING)
                    & (TestCase.lease_expires_at.is_not(None))
                    & (TestCase.lease_expires_at <= datetime.now(UTC))
                ),
            ),
        ).order_by(TestCase.id).all()
        published = 0
        with task_app.producer_or_acquire() as producer:
            for offset in range(0, len(rows), batch_size):
                batch = [int(row[0]) for row in rows[offset:offset + batch_size]]
                task_app.send_task(
                    "scale_probe_batch",
                    args=[batch, execution_delay_ms],
                    queue="recovery",
                    producer=producer,
                    ignore_result=True,
                )
                published += len(batch)
        return {"published": published, "message_batch_size": batch_size}
    finally:
        db.close()


@task_app.task(
    name="append_audit_event",
    acks_late=True,
    reject_on_worker_lost=True,
    ignore_result=True,
)
def append_audit_event_task(**event):
    from backend_api.db.base import SessionLocal
    from backend_api.services.audit_service import AuditService

    db = SessionLocal()
    try:
        AuditService.record(db, **event)
    finally:
        db.close()


@task_app.task(name="retention_sweep", ignore_result=True)
def retention_sweep_task():
    from backend_api.db.base import SessionLocal
    from backend_api.services.retention_service import RetentionService

    db = SessionLocal()
    try:
        return RetentionService.sweep(db, apply=True)
    finally:
        db.close()
