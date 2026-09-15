"""Authoritative Oracle callback classification.

Historically two endpoints (``oracle_server/main.py`` and ``backend_api/routers/oracle.py``)
each implemented half of the correct callback logic: one had the ``kind=execution`` vs. taint
distinction but never rejected a re-used token; the other rejected consumed tokens but treated
*every* callback — including source-read telemetry — as a confirmed XSS. This module is the single
source of truth both now call, enforcing the full contract:

    unknown token   → 404
    expired token   → 410
    consumed token  → 410 (replay)
    taint/telemetry → recorded, NOT a HIT, token NOT consumed
    execution proof → token consumed atomically (one winner), HIT, finding

The consume step is a conditional UPDATE guarded on ``token_consumed_at IS NULL`` so two
simultaneous execution callbacks cannot both win the token.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from backend_api.models.execution import Execution, OracleStatus
from backend_api.models.test_case import TestCase
from backend_api.utils.logger import logger
from backend_api.utils.log_serializer import parse_execution_logs, serialize_execution_logs


def _legacy_callback_confirms_execution(token: str, sink: Optional[str], data: Optional[str]) -> bool:
    """Conservatively classify callbacks from pre-``kind`` oracle scripts.

    Reaching innerHTML, setAttribute, or another taint sink is not proof that code executed.
    Legacy callbacks are accepted as execution only when they carry direct execution evidence
    tied to this test token.
    """
    if not sink:
        return False
    normalized_sink = str(sink).strip()
    sink_lower = normalized_sink.lower()
    if normalized_sink == token or token in normalized_sink:
        return True
    if sink_lower in {"taggedtemplateliteral", "directexecution"}:
        return True
    if sink_lower in {"alert", "prompt", "confirm"}:
        return bool(data and token in data)
    return False


def classify_callback(token: str, kind: Optional[str], sink: Optional[str], data: Optional[str]) -> bool:
    """Return True only when the callback is proof of code execution (a HIT)."""
    if kind is not None:
        return str(kind).strip().lower() == "execution"
    return _legacy_callback_confirms_execution(token, sink, data)


def _token_is_expired(test_case: TestCase, now: datetime) -> bool:
    exp = test_case.token_expires_at
    if not exp:
        return False
    # Tolerate naive datetimes stored by some DB backends.
    ref = now if exp.tzinfo else now.replace(tzinfo=None)
    return exp < ref


def _record_dynamic_sink(db: Session, test_case: TestCase, sink: Optional[str], data: Optional[str]) -> Optional[int]:
    """Resolve or create a DYNAMIC Sink row from callback telemetry. Best-effort."""
    if not test_case.context_id or not sink:
        return None
    try:
        import json
        from backend_api.models.sink import Sink, DetectedVia

        js_location = "unknown"
        notes_trace = ""
        if data:
            try:
                parsed = json.loads(data)
                if isinstance(parsed, dict):
                    js_location = f"{parsed.get('filename', 'unknown')}:{parsed.get('line', 0)}:{parsed.get('column', 0)}"
                    notes_trace = f"Value: {str(parsed.get('value', ''))[:200]}\nStack: {parsed.get('stack', '')}"
            except Exception as parse_err:
                logger.error(f"Error parsing data payload for dynamic sink: {parse_err}")

        existing = (
            db.query(Sink)
            .filter(Sink.context_id == test_case.context_id)
            .filter(Sink.sink_type == sink)
            .filter(Sink.detected_via == DetectedVia.DYNAMIC)
            .first()
        )
        if existing:
            existing.js_location = js_location
            existing.notes = f"Dynamically hit during browser fuzzing.\n{notes_trace}"
            db.commit()
            return existing.id

        dynamic_sink = Sink(
            context_id=test_case.context_id,
            sink_type=sink,
            js_location=js_location,
            detected_via=DetectedVia.DYNAMIC,
            notes=f"Dynamically hit during browser fuzzing.\n{notes_trace}",
        )
        db.add(dynamic_sink)
        db.commit()
        db.refresh(dynamic_sink)
        logger.info(f"Dynamically registered new Sink id={dynamic_sink.id} for context_id={test_case.context_id}")
        return dynamic_sink.id
    except Exception as sink_err:
        logger.error(f"Failed to record dynamic sink: {sink_err}", exc_info=True)
        return None


def _atomic_consume(db: Session, test_case_id: int, now: datetime) -> bool:
    """Consume the token iff not already consumed. Returns True for the sole winner.

    A conditional UPDATE on ``token_consumed_at IS NULL`` makes the consume atomic, so two
    concurrent execution callbacks cannot both be credited with the HIT.
    """
    updated = (
        db.query(TestCase)
        .filter(TestCase.id == test_case_id, TestCase.token_consumed_at.is_(None))
        .update({TestCase.token_consumed_at: now}, synchronize_session=False)
    )
    db.commit()
    return bool(updated)


def process_oracle_callback(
    db: Session,
    token: str,
    *,
    kind: Optional[str] = None,
    sink: Optional[str] = None,
    data: Optional[str] = None,
    msg: Optional[str] = None,
    create_finding: bool = False,
) -> Dict[str, Any]:
    """Validate, classify, and record a single Oracle callback.

    Raises ``HTTPException`` (404/410) for unknown / expired / consumed tokens so every caller
    surfaces identical status codes. On an execution HIT the token is consumed atomically; on a
    taint/telemetry callback the token is left unconsumed and only telemetry is recorded.
    """
    now = datetime.now(UTC)

    test_case = db.query(TestCase).filter(TestCase.token == token).first()
    if not test_case:
        logger.warning("Oracle callback used an unknown token")
        raise HTTPException(status_code=404, detail="Token not found")
    if _token_is_expired(test_case, now):
        logger.warning("Rejected expired oracle callback")
        raise HTTPException(status_code=410, detail="Token expired")
    if test_case.token_consumed_at:
        logger.warning("Rejected replay of an already-consumed oracle token")
        raise HTTPException(status_code=410, detail="Token already consumed")

    is_execution = classify_callback(token, kind, sink, data)
    logger.info(f"Oracle callback test_case_id={test_case.id} kind={kind!r} sink={sink!r} execution={is_execution}")

    # Atomically consume on a genuine execution proof; a lost race means someone already won.
    if is_execution:
        if not _atomic_consume(db, test_case.id, now):
            logger.warning("Concurrent oracle callback lost the consume race")
            raise HTTPException(status_code=410, detail="Token already consumed")

    # Find or create the execution record.
    execution = (
        db.query(Execution)
        .filter(Execution.test_case_id == test_case.id)
        .order_by(Execution.executed_at.desc())
        .first()
    )
    if not execution:
        execution = Execution(
            test_case_id=test_case.id,
            oracle_status=OracleStatus.HIT if is_execution else OracleStatus.MISSED,
            oracle_token=token if is_execution else None,
            executed_at=now,
        )
        db.add(execution)
    else:
        if is_execution:
            execution.oracle_status = OracleStatus.HIT
            execution.oracle_token = token
        execution.executed_at = now

    # Record telemetry (sink/data) for both taint and execution callbacks.
    dynamic_sink_id = None
    if sink or data:
        logs = parse_execution_logs(execution.logs)
        logs["sink"] = sink
        logs["data"] = data
        if kind:
            logs["kind"] = kind
        execution.logs = serialize_execution_logs(
            logs,
            test_case_id=execution.test_case_id,
            attempt_no=execution.attempt_no,
        )
        dynamic_sink_id = _record_dynamic_sink(db, test_case, sink, data)

    db.commit()
    db.refresh(execution)

    finding_id = None
    if is_execution and create_finding:
        try:
            from backend_api.services.result_service import ResultService

            finding = ResultService.create_finding_from_execution(db, execution_id=execution.id, sink_id=dynamic_sink_id)
            if finding:
                finding_id = finding.id
                logger.info(f"Auto-generated Finding id={finding.id} for hit on test_case={test_case.id}")
        except Exception as finding_err:
            logger.error(f"Failed to auto-generate Finding for execution {execution.id}: {finding_err}")

    return {
        "is_execution": is_execution,
        "test_case_id": test_case.id,
        "execution_id": execution.id,
        "dynamic_sink_id": dynamic_sink_id,
        "finding_id": finding_id,
    }
