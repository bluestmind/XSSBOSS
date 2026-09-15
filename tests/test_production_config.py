from pathlib import Path

import pytest

from backend_api.config import Settings


ROOT = Path(__file__).resolve().parents[1]


def test_production_rejects_local_unsafe_dependencies():
    config = Settings(
        ENVIRONMENT="production",
        DATABASE_URL="sqlite:///local.db",
        ORCHESTRATION_MODE="inline",
        SECRET_KEY="change-me-in-production",
        API_AUTH_TOKEN=None,
        RATE_LIMIT_REDIS_ENABLED=False,
        RATE_LIMIT_REDIS_REQUIRED=False,
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
        RATE_LIMIT_REDIS_ENABLED=True,
        RATE_LIMIT_REDIS_REQUIRED=True,
        ALLOWED_ORIGINS=["https://scanner.example.test"],
    )
    config.validate_runtime()


def test_production_rejects_invalid_runtime_lineage_key_version():
    config = Settings(
        ENVIRONMENT="production",
        DATABASE_URL="postgresql://xssboss:secret@postgres/xssboss",
        ORCHESTRATION_MODE="celery",
        AUDIT_MODE="celery",
        SECRET_KEY="s" * 40,
        API_AUTH_TOKEN="a" * 40,
        RATE_LIMIT_REDIS_ENABLED=True,
        RATE_LIMIT_REDIS_REQUIRED=True,
        ALLOWED_ORIGINS=["https://scanner.example.test"],
        RUNTIME_LINEAGE_HMAC_KEY_VERSION="bad version!",
    )

    with pytest.raises(RuntimeError, match="RUNTIME_LINEAGE_HMAC_KEY_VERSION"):
        config.validate_runtime()


def test_dockerfile_copies_the_checked_in_migration_config():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert (ROOT / "backend_api" / "alembic.ini").is_file()
    assert (
        "COPY --chown=xssboss:xssboss backend_api/alembic.ini "
        "/app/backend_api/alembic.ini"
    ) in dockerfile
    assert "COPY --chown=xssboss:xssboss alembic.ini /app/alembic.ini" not in dockerfile
    assert "ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright" in dockerfile
    assert "chown -R xssboss:xssboss /ms-playwright" in dockerfile


def test_production_compose_declares_services_and_forwards_hunter_controls():
    compose_path = ROOT / "compose.production.yml"
    compose_text = compose_path.read_text(encoding="utf-8")
    for service in ("api", "orchestrator", "browser-worker", "audit-worker"):
        assert f"  {service}:" in compose_text

    required_controls = {
        "ORACLE_SERVER_URL",
        "PROXY_ENABLED",
        "WAF_BYPASS_HEADERS",
        "ALLOW_INSECURE_TLS",
        "BROWSER_NAVIGATION_TIMEOUT",
        "ORACLE_WAIT_TIMEOUT",
        "MAX_PAYLOADS_PER_CONTEXT",
        "MAX_TEST_CASES_PER_EXPERIMENT",
        "REQUEST_DELAY_MS",
        "MAX_REQUESTS_PER_MINUTE",
        "RATE_LIMIT_REDIS_ENABLED",
        "RATE_LIMIT_REDIS_REQUIRED",
        "CIRCUIT_BREAKER_ENABLED",
    }

    for control in required_controls:
        assert f"      {control}:" in compose_text
    assert (
        "ORACLE_SERVER_URL: ${ORACLE_SERVER_URL:?set browser-reachable "
        "ORACLE_SERVER_URL}"
    ) in compose_text
    assert "USE_UNDETECTED_CHROME: ${USE_UNDETECTED_CHROME:-False}" in compose_text
    assert '      API_AUTH_TOKEN: ""' in compose_text


def test_production_example_defaults_to_the_safe_high_yield_profile():
    values = {}
    for raw_line in (ROOT / ".env.production.example").read_text(
        encoding="utf-8"
    ).splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value

    assert values["ORACLE_SERVER_URL"].startswith("https://")
    assert values["USE_UNDETECTED_CHROME"] == "False"
    for key in (
        "PROXY_ENABLED",
        "UPSTREAM_ROTATING_PROXY_ENABLED",
        "WAF_BYPASS_HEADERS",
        "ALLOW_INSECURE_TLS",
        "BURP_ENABLED",
        "LLM_ENABLED",
        "RUNTIME_LINEAGE_AAB_PROBES",
    ):
        assert values[key] == "False"
    assert values["MAX_PAYLOADS_PER_CONTEXT"] == "32"
    assert values["MAX_TEST_CASES_PER_EXPERIMENT"] == "1500"
    assert values["MAX_QUEUE_ACTIVE"] == "1"
    assert values["MAX_REQUESTS_PER_MINUTE"] == "40"
    assert values["RATE_LIMIT_REDIS_ENABLED"] == "True"
    assert values["RATE_LIMIT_REDIS_REQUIRED"] == "True"


def test_windows_launcher_uses_the_safe_high_yield_profile():
    launcher = (ROOT / "run_all.bat").read_text(encoding="utf-8")

    for assignment in (
        'set "MAX_QUEUE_ACTIVE=1"',
        'set "MAX_PROFILING_WORKERS=1"',
        'set "MAX_PAYLOADS_PER_CONTEXT=32"',
        'set "MAX_TEST_CASES_PER_EXPERIMENT=1500"',
        'set "REQUEST_DELAY_MS=1200"',
        'set "MAX_REQUESTS_PER_MINUTE=40"',
        'set "RATE_LIMIT_REDIS_ENABLED=False"',
        'set "RATE_LIMIT_REDIS_REQUIRED=False"',
        'set "PROXY_ENABLED=False"',
        'set "BURP_PROXY_WORKERS=False"',
        'set "WAF_BYPASS_HEADERS=False"',
        'set "ALLOW_INSECURE_TLS=False"',
    ):
        assert assignment in launcher
    assert "set BURP_PROXY_WORKERS=True" not in launcher
