"""Database session management."""
from sqlalchemy.orm import Session
from .base import SessionLocal


def get_db() -> Session:
    """Get database session (dependency for FastAPI)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
