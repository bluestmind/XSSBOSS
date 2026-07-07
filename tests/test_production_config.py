import pytest

from backend_api.config import Settings


def test_production_rejects_local_unsafe_dependencies():
    config = Settings(
        ENVIRONMENT="production",
        DATABASE_URL="sqlite:///local.db",
        ORCHESTRATION_MODE="inline",
        SECRET_KEY="change-me-in-production",
        API_AUTH_TOKEN=None,
        ALLOWED_ORIGINS=["http://localhost:3000"],
    )
    with pytest.raises(RuntimeError, match="PostgreSQL.*celery.*SECRET_KEY.*API_AUTH_TOKEN"):
        config.validate_runtime()


def test_production_accepts_durable_authenticated_configuration():
    config = Settings(
        ENVIRONMENT="production",
        DATABASE_URL="postgresql://xssboss:secret@postgres/xssboss",
        ORCHESTRATION_MODE="celery",
        AUDIT_MODE="celery",
        SECRET_KEY="s" * 40,
        API_AUTH_TOKEN="a" * 40,
        ALLOWED_ORIGINS=["https://scanner.example.test"],
    )
    config.validate_runtime()
