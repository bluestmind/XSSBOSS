import pytest

from backend_api.config import settings
from backend_api.utils.rate_limiter import (
    CircuitOpenError,
    RateLimiter,
    RequestBudgetExceeded,
)


class _Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class _BrokenRedis:
    def eval(self, *args, **kwargs):
        raise ConnectionError("redis unavailable")


def _configure(monkeypatch, *, required=False):
    monkeypatch.setattr(settings, "REQUEST_DELAY_MS", 0)
    monkeypatch.setattr(settings, "MAX_REQUESTS_PER_MINUTE", 40)
    monkeypatch.setattr(settings, "JITTER_FACTOR", 0.0)
    monkeypatch.setattr(settings, "CIRCUIT_BREAKER_ENABLED", False)
    monkeypatch.setattr(settings, "RATE_LIMIT_REDIS_REQUIRED", required)
    monkeypatch.setattr(settings, "RATE_LIMIT_REDIS_RETRY_SECS", 30.0)


def test_target_identity_is_per_origin_and_normalizes_default_ports():
    assert RateLimiter._target_identity("https://EXAMPLE.test/a") == "https://example.test:443"
    assert RateLimiter._target_identity("https://example.test:443/b") == "https://example.test:443"
    assert RateLimiter._target_identity("https://example.test:8443/") == "https://example.test:8443"


def test_required_shared_backend_fails_closed(monkeypatch):
    _configure(monkeypatch, required=True)
    clock = _Clock()
    limiter = RateLimiter(
        redis_client=_BrokenRedis(),
        use_redis=True,
        sleeper=clock.sleep,
        monotonic=clock.monotonic,
    )

    with pytest.raises(CircuitOpenError, match="backend unavailable"):
        limiter.wait_for_slot("https://app.test/path")
    assert clock.sleeps == []


def test_optional_redis_fallback_divides_allowance_across_workers(monkeypatch):
    _configure(monkeypatch, required=False)
    clock = _Clock()
    limiter = RateLimiter(
        redis_client=_BrokenRedis(),
        use_redis=True,
        sleeper=clock.sleep,
        monotonic=clock.monotonic,
        fallback_worker_estimate=4,
    )

    for _ in range(10):
        limiter.wait_for_slot("https://app.test/path")
    limiter.wait_for_slot("https://app.test/path")

    assert len(clock.sleeps) == 1
    assert clock.sleeps[0] == pytest.approx(60.0)
    assert limiter.get_status("https://app.test/path")["max_requests_per_minute"] == 10


def test_retry_after_http_date_and_seconds_are_bounded(monkeypatch):
    _configure(monkeypatch)
    limiter = RateLimiter(use_redis=False, wall_time=lambda: 1_000.0)
    assert limiter._retry_after_seconds("12") == 12.0
    assert limiter._retry_after_seconds("999999") == 86_400.0
    assert limiter._retry_after_seconds("not-a-date") is None


def test_stage_request_budget_counts_slots_and_fails_closed(monkeypatch):
    _configure(monkeypatch)
    limiter = RateLimiter(use_redis=False)

    with limiter.request_budget(2) as meter:
        limiter.wait_for_slot("https://app.test/one")
        limiter.wait_for_slot("https://app.test/two")
        with pytest.raises(RequestBudgetExceeded, match="2/2"):
            limiter.wait_for_slot("https://app.test/three")

    assert meter.used == 2
