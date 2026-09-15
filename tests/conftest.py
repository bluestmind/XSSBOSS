"""Pytest configuration and global fixtures for isolated testing."""
import os
import sys
import pytest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Force environment to 'test' so backend_api.config.settings routes to test database
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite:///./xssboss_test.db"

from backend_api.db.test_db import get_test_engine, wipe_test_db
from backend_api.db.session import get_db
from backend_api.models.base import Base
from backend_api.models.target import Target
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from sqlalchemy.orm import sessionmaker


@pytest.fixture(scope="session")
def engine():
    """Session-scoped test engine with a fresh checked-in model schema."""
    eng = get_test_engine()
    # ``create_all`` does not add columns to an interrupted run's existing
    # SQLite file. Rebuild the disposable test database up front so model and
    # schema cannot drift when a migration adds an ORM field.
    wipe_test_db(eng)
    yield eng
    # Clean up at end of test run
    wipe_test_db(eng)


@pytest.fixture(scope="function")
def db_session(engine):
    """Function-scoped database session providing clean isolation for each test."""
    connection = engine.connect()
    transaction = connection.begin()
    SessionLocal = sessionmaker(bind=connection, autocommit=False, autoflush=False)
    session = SessionLocal()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture(scope="function")
def test_target(db_session):
    """Fixture providing a standard test target."""
    target = Target(
        name="Test Target Benchmark",
        base_url="https://test.xssboss.local",
        is_active=True,
    )
    db_session.add(target)
    db_session.flush()
    return target
