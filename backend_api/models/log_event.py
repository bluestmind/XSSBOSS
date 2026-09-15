"""SQLAlchemy model for pipeline diagnostic logs."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Index
from backend_api.models.base import BaseModel


class LogEvent(BaseModel):
    """Pipeline diagnostic log entry capturing runtime actions, warnings, errors, and hits."""
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True, nullable=False)
    level = Column(String(20), default="INFO", index=True, nullable=False)
    module = Column(String(50), default="system", index=True, nullable=False)
    experiment_id = Column(Integer, nullable=True, index=True)
    target_id = Column(Integer, nullable=True, index=True)
    message = Column(Text, nullable=False)
    detail = Column(Text, nullable=True)
    data = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_log_events_timestamp_level", "timestamp", "level"),
        Index("ix_log_events_exp_module", "experiment_id", "module"),
    )

    def to_dict(self):
        """Serialize log event to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "level": self.level,
            "module": self.module,
            "experiment_id": self.experiment_id,
            "target_id": self.target_id,
            "message": self.message,
            "detail": self.detail,
            "data": self.data or {},
        }
