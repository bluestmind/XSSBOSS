"""Database initialization."""
"""Database initialization."""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend_api.config import settings
from backend_api.models.base import Base
import backend_api.models  # noqa: F401 - register all SQLAlchemy models

# Create engine
_connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    _connect_args = {"timeout": 60.0, "check_same_thread": False}

engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    echo=False,  # Set to True for SQL query logging
    connect_args=_connect_args,
)

# Enable WAL mode for SQLite so readers don't block writers
if settings.DATABASE_URL.startswith("sqlite"):
    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def _set_wal_mode(dbapi_conn, _):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA busy_timeout=60000;")
        cursor.execute("PRAGMA cache_size=-64000;")
        cursor.execute("PRAGMA temp_store=MEMORY;")
        cursor.close()

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Bring the database to the checked-in schema revision."""
    from alembic import command
    from alembic.config import Config
    from pathlib import Path

    project_root = Path(__file__).resolve().parents[2]
    config = Config(str(project_root / "backend_api" / "alembic.ini"))
    config.set_main_option("script_location", str(project_root / "backend_api" / "db" / "migrations"))
    config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)
    command.upgrade(config, "head")


def get_db():
    """Get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
