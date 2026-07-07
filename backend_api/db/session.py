"""Database session management."""
from sqlalchemy.orm import Session
from .base import SessionLocal
from backend_api.tenancy import current_tenant_id  # noqa: F401 - registers ORM isolation hooks


def get_db() -> Session:
    """Get database session (dependency for FastAPI)."""
    db = SessionLocal()
    tenant_id = current_tenant_id.get()
    if tenant_id is not None:
        db.info["tenant_id"] = tenant_id
    try:
        yield db
    finally:
        db.close()
