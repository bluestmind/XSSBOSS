"""Isolated Test Database Factory and Utilities.

Ensures automated tests, benchmarks, and fixtures execute in a dedicated, isolated SQLite database
(or in-memory database) so that production data, bug bounty scopes, and findings in `xssboss.db`
remain completely unpolluted and untouched.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Generator, Optional
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from backend_api.models.base import Base
import backend_api.models  # noqa: F401 - ensure all models are registered
from backend_api.utils.logger import logger

TEST_DB_PATH = Path(__file__).resolve().parents[2] / "xssboss_test.db"
TEST_DATABASE_URL = f"sqlite:///{TEST_DB_PATH}"


def get_test_engine(db_url: Optional[str] = None):
    """Create an isolated SQLAlchemy engine for testing with SQLite WAL mode."""
    url = db_url or TEST_DATABASE_URL
    _connect_args = {"timeout": 30.0, "check_same_thread": False} if url.startswith("sqlite") else {}

    engine = create_engine(url, pool_pre_ping=True, echo=False, connect_args=_connect_args)

    if url.startswith("sqlite") and ":memory:" not in url:
        @event.listens_for(engine, "connect")
        def _set_test_wal_mode(dbapi_conn, _):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA busy_timeout=30000;")
            cursor.close()

    return engine


def init_test_db(engine=None):
    """Create all database tables on the test database."""
    test_eng = engine or get_test_engine()
    Base.metadata.create_all(bind=test_eng)
    return test_eng


def wipe_test_db(engine=None):
    """Drop and recreate all database tables on the test database."""
    test_eng = engine or get_test_engine()
    Base.metadata.drop_all(bind=test_eng)
    Base.metadata.create_all(bind=test_eng)


def get_test_db_session(engine=None) -> Generator[Session, None, None]:
    """Yield an isolated test session that rolls back or cleans up after use."""
    test_eng = engine or get_test_engine()
    init_test_db(test_eng)
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_eng)
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()
