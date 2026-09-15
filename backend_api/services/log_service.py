"""Central Structured Logging & Diagnostic Telemetry Service."""
from __future__ import annotations

import asyncio
import json
import logging
import re
from collections import deque
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional
from sqlalchemy import desc
from sqlalchemy.orm import Session

from backend_api.db.session import SessionLocal
from backend_api.models.log_event import LogEvent


class DiagnosticRingBuffer:
    """Thread-safe in-memory ring buffer for low-latency live streaming."""
    def __init__(self, maxlen: int = 3000):
        self.buffer: deque[Dict[str, Any]] = deque(maxlen=maxlen)
        self._listeners: List[asyncio.Queue] = []

    def append(self, event: Dict[str, Any]) -> None:
        self.buffer.append(event)
        for queue in list(self._listeners):
            try:
                queue.put_nowait(event)
            except Exception:
                pass

    def get_recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        items = list(self.buffer)
        return items[-limit:]

    def add_listener(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._listeners.append(queue)
        return queue

    def remove_listener(self, queue: asyncio.Queue) -> None:
        if queue in self._listeners:
            self._listeners.remove(queue)


ring_buffer = DiagnosticRingBuffer()


class LogService:
    """Core service for capturing, indexing, querying, and streaming diagnostic logs."""

    _SENSITIVE_KEYS = {
        "authorization", "proxy-authorization", "cookie", "set-cookie",
        "password", "passwd", "secret", "api_key", "apikey", "access_token",
        "refresh_token", "session", "sessionid", "csrf", "xsrf",
    }

    @classmethod
    def _sanitize(cls, value: Any, key: str = "", depth: int = 0) -> Any:
        """Redact credentials while retaining payloads and diagnostic structure."""
        if depth > 10:
            return "[MAX_DEPTH]"
        normalized_key = str(key).lower().replace("-", "_")
        if normalized_key in {item.replace("-", "_") for item in cls._SENSITIVE_KEYS}:
            return "[REDACTED]"
        if isinstance(value, dict):
            return {
                str(item_key): cls._sanitize(item_value, str(item_key), depth + 1)
                for item_key, item_value in value.items()
            }
        if isinstance(value, (list, tuple, set)):
            return [cls._sanitize(item, key, depth + 1) for item in value]
        if isinstance(value, str):
            text = value
            text = re.sub(
                r"(?i)\b(https?://)([^/@\s:]+):([^/@\s]+)@",
                r"\1[REDACTED]:[REDACTED]@",
                text,
            )
            text = re.sub(
                r"(?i)(authorization|proxy-authorization)\s*[:=]\s*(bearer\s+|basic\s+)?[^\s,;]+",
                r"\1: [REDACTED]",
                text,
            )
            text = re.sub(
                r"(?i)(cookie|set-cookie|password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*[^\r\n&,;]+",
                r"\1=[REDACTED]",
                text,
            )
            return text
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if hasattr(value, "value"):
            return cls._sanitize(value.value, key, depth + 1)
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)

    @classmethod
    def emit(
        cls,
        level: str,
        module: str,
        message: str,
        detail: Optional[str] = None,
        experiment_id: Optional[int] = None,
        target_id: Optional[int] = None,
        data: Optional[Dict[str, Any]] = None,
        db: Optional[Session] = None,
    ) -> Dict[str, Any]:
        """Emit a structured diagnostic log event."""
        now = datetime.now(timezone.utc)
        level_upper = level.upper()
        safe_message = cls._sanitize(str(message))
        safe_detail = cls._sanitize(str(detail)) if detail is not None else None
        safe_data = cls._sanitize(data or {})
        event_dict = {
            "id": int(now.timestamp() * 1000),
            "timestamp": now.isoformat(),
            "level": level_upper,
            "module": module.lower(),
            "experiment_id": experiment_id,
            "target_id": target_id,
            "message": safe_message,
            "detail": safe_detail,
            "data": safe_data,
        }

        # Broadcast to in-memory ring buffer
        ring_buffer.append(event_dict)

        # Persist to database
        own_session = False
        if db is None:
            db = SessionLocal()
            own_session = True

        try:
            log_entry = LogEvent(
                timestamp=now,
                level=level_upper,
                module=module.lower(),
                experiment_id=experiment_id,
                target_id=target_id,
                message=safe_message,
                detail=safe_detail,
                data=safe_data,
            )
            db.add(log_entry)
            db.commit()
            db.refresh(log_entry)
            event_dict["id"] = log_entry.id
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        finally:
            if own_session:
                db.close()

        return event_dict

    @classmethod
    def info(cls, module: str, message: str, detail: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        return cls.emit("INFO", module, message, detail=detail, **kwargs)

    @classmethod
    def warn(cls, module: str, message: str, detail: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        return cls.emit("WARNING", module, message, detail=detail, **kwargs)

    @classmethod
    def error(cls, module: str, message: str, detail: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        return cls.emit("ERROR", module, message, detail=detail, **kwargs)

    @classmethod
    def hit(cls, module: str, message: str, detail: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        return cls.emit("HIT", module, message, detail=detail, **kwargs)

    @classmethod
    def debug(cls, module: str, message: str, detail: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        return cls.emit("DEBUG", module, message, detail=detail, **kwargs)

    @staticmethod
    def get_logs(
        db: Session,
        level: Optional[str] = None,
        module: Optional[str] = None,
        experiment_id: Optional[int] = None,
        target_id: Optional[int] = None,
        search: Optional[str] = None,
        since_id: Optional[int] = None,
        limit: int = 150,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Query diagnostic logs from DB with multi-facet filters."""
        query = db.query(LogEvent)

        if level and level.upper() != "ALL":
            query = query.filter(LogEvent.level == level.upper())
        if module and module.lower() != "all":
            query = query.filter(LogEvent.module == module.lower())
        if experiment_id:
            query = query.filter(LogEvent.experiment_id == experiment_id)
        if target_id:
            query = query.filter(LogEvent.target_id == target_id)
        if since_id:
            query = query.filter(LogEvent.id > since_id)
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                (LogEvent.message.ilike(search_pattern))
                | (LogEvent.detail.ilike(search_pattern))
                | (LogEvent.module.ilike(search_pattern))
            )

        total_count = query.count()
        logs = query.order_by(desc(LogEvent.id)).offset(offset).limit(limit).all()

        return {
            "total": total_count,
            "offset": offset,
            "limit": limit,
            "logs": [log.to_dict() for log in logs],
        }

    @staticmethod
    def get_stats(db: Session, experiment_id: Optional[int] = None) -> Dict[str, Any]:
        """Get aggregate counts for log levels and modules."""
        query = db.query(LogEvent)
        if experiment_id:
            query = query.filter(LogEvent.experiment_id == experiment_id)

        total = query.count()
        hits = query.filter(LogEvent.level == "HIT").count()
        errors = query.filter(LogEvent.level == "ERROR").count()
        warnings = query.filter(LogEvent.level == "WARNING").count()
        infos = query.filter(LogEvent.level == "INFO").count()
        debugs = query.filter(LogEvent.level == "DEBUG").count()

        # Modules breakdown
        from sqlalchemy import func
        module_rows = (
            db.query(LogEvent.module, func.count(LogEvent.id))
            .filter(LogEvent.experiment_id == experiment_id if experiment_id else True)
            .group_by(LogEvent.module)
            .all()
        )
        module_counts = {row[0]: row[1] for row in module_rows}

        return {
            "total": total,
            "hits": hits,
            "errors": errors,
            "warnings": warnings,
            "info": infos,
            "debug": debugs,
            "modules": module_counts,
        }

    @staticmethod
    def clear_logs(db: Session, experiment_id: Optional[int] = None) -> int:
        """Clear log entries."""
        query = db.query(LogEvent)
        if experiment_id:
            query = query.filter(LogEvent.experiment_id == experiment_id)
        deleted = query.delete(synchronize_session=False)
        db.commit()
        return deleted

    @staticmethod
    async def stream_logs() -> AsyncGenerator[str, None]:
        """SSE generator streaming live diagnostic events."""
        queue = ring_buffer.add_listener()
        try:
            # Yield initial connect handshake
            yield f"data: {json.dumps({'type': 'connected', 'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=25.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive heartbeat comment
                    yield ": heartbeat\n\n"
        finally:
            ring_buffer.remove_listener(queue)


class PythonLogHandlerBridge(logging.Handler):
    """Bridge connecting standard Python logging directly into LogService."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            # Prevent infinite recursion for internal DB logging
            if record.name.startswith("sqlalchemy") or record.name.startswith("uvicorn.access"):
                return

            module = record.name.split(".")[-1]
            level = record.levelname
            msg = self.format(record) if not record.msg else str(record.getMessage())
            detail = None
            if record.exc_info:
                import traceback
                detail = "".join(traceback.format_exception(*record.exc_info))

            # Infer experiment_id or target_id from record args if present
            experiment_id = getattr(record, "experiment_id", None)
            target_id = getattr(record, "target_id", None)

            # Route to ring buffer only for high throughput standard logs
            now = datetime.now(timezone.utc)
            ring_buffer.append({
                "id": int(now.timestamp() * 1000),
                "timestamp": now.isoformat(),
                "level": level.upper(),
                "module": module.lower(),
                "experiment_id": experiment_id,
                "target_id": target_id,
                "message": msg,
                "detail": detail,
                "data": {},
            })
        except Exception:
            pass
