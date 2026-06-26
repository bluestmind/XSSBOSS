"""Database initialization."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend_api.config import settings
from backend_api.models.base import Base
import backend_api.models  # noqa: F401 - register all SQLAlchemy models

# Create engine
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    echo=False,  # Set to True for SQL query logging
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)
    # Safely alter schema if burp_flagged column doesn't exist
    from sqlalchemy import text
    with engine.begin() as conn:
        try:
            conn.execute(text("ALTER TABLE params ADD COLUMN burp_flagged BOOLEAN DEFAULT 0"))
        except Exception:
            pass
        for statement in [
            "ALTER TABLE findings ADD COLUMN vuln_type VARCHAR(80) DEFAULT 'xss' NOT NULL",
            "ALTER TABLE findings ADD COLUMN scanner_module VARCHAR(120) DEFAULT 'xss_fuzzer' NOT NULL",
            "ALTER TABLE findings ADD COLUMN confidence VARCHAR(40) DEFAULT 'firm' NOT NULL",
            "ALTER TABLE findings ADD COLUMN evidence_summary TEXT",
        ]:
            try:
                conn.execute(text(statement))
            except Exception:
                pass


def get_db():
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
