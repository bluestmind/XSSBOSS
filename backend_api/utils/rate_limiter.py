"""Shared per-target request throttling and circuit breaking.

Redis coordinates reservations when configured and reachable. Every rolling
window check and circuit transition is atomic across crawler, profiler, API,
and browser processes. Redis loss falls back to a deliberately reduced,
thread-safe local allowance so an infrastructure failure cannot multiply the
configured target rate by the expected worker count.
"""

from __future__ import annotations

import enum
import hashlib
import random
import threading
import time
import uuid
from collections import deque
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable, TypeVar
from urllib.parse import urlparse

from backend_api.config import settings
from backend_api.utils.logger import logger


class CircuitState(enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(RuntimeError):
    """The target circuit is open or its single recovery probe is active."""


class RequestBudgetExceeded(CircuitOpenError):
    """The current bounded operation has no outbound target requests left."""


@dataclass
class RequestBudgetMeter:
    limit: int
    used: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def reserve(self) -> None:
        with self._lock:
            if self.used >= self.limit:
                raise RequestBudgetExceeded(
                    f"Outbound request budget exhausted ({self.used}/{self.limit})"
                )
            self.used += 1


_active_request_budget: ContextVar[RequestBudgetMeter | None] = ContextVar(
    "xssboss_active_request_budget",
    default=None,
)


@dataclass(frozen=True)
class _ReservationDecision:
    allowed: bool
    wait_seconds: float = 0.0
    circuit_open: bool = False


class _HostBucket:
    __slots__ = (
        "lock", "last_request_at", "current_delay_ms", "timestamps",
        "consecutive_errors", "circuit_state", "circuit_opened_at",
        "half_open_in_flight", "half_open_until", "retry_after_until",
    )

    def __init__(self, base_delay_ms: int):
        self.lock = threading.Lock()
        self.last_request_at = 0.0
        self.current_delay_ms = max(0, base_delay_ms)
        self.timestamps: deque[float] = deque()
        self.consecutive_errors = 0
        self.circuit_state = CircuitState.CLOSED
        self.circuit_opened_at = 0.0
        self.half_open_in_flight = False
        self.half_open_until = 0.0
        self.retry_after_until = 0.0


# Redis TIME avoids cross-host clock skew. Both keys share a Redis Cluster hash
# tag, and the allow decision plus ZADD form one indivisible reservation.
_RESERVE_SCRIPT = r"""
local state_key = KEYS[1]
local window_key = KEYS[2]
local t = redis.call('TIME')
local now = (tonumber(t[1]) * 1000) + math.floor(tonumber(t[2]) / 1000)
local window_ms = tonumber(ARGV[1])
local request_limit = tonumber(ARGV[2])
local base_delay_ms = tonumber(ARGV[3])
local jitter_multiplier = tonumber(ARGV[4])
local circuit_enabled = tonumber(ARGV[5])
local recovery_ms = tonumber(ARGV[6])
local member = ARGV[7]
local state_ttl = tonumber(ARGV[8])

local circuit = redis.call('HGET', state_key, 'circuit') or 'closed'
local opened_ms = tonumber(redis.call('HGET', state_key, 'opened_ms') or '0')
local half_open_until = tonumber(redis.call('HGET', state_key, 'half_open_until') or '0')
if circuit_enabled == 1 and circuit == 'open' then
    local remaining = recovery_ms - (now - opened_ms)
    if remaining > 0 then return {0, remaining, 'circuit_open'} end
    circuit = 'half_open'
    redis.call('HSET', state_key, 'circuit', circuit, 'half_open_until', 0)
elseif circuit_enabled == 1 and circuit == 'half_open' and half_open_until > now then
    return {0, half_open_until - now, 'circuit_open'}
end

local retry_ms = tonumber(redis.call('HGET', state_key, 'retry_ms') or '0')
if retry_ms > now then return {0, retry_ms - now, 'retry_after'} end

redis.call('ZREMRANGEBYSCORE', window_key, '-inf', now - window_ms)
local count = tonumber(redis.call('ZCARD', window_key))
if count >= request_limit then
    local oldest = redis.call('ZRANGE', window_key, 0, 0, 'WITHSCORES')
    local wait_ms = window_ms
    if oldest[2] then wait_ms = math.max(1, tonumber(oldest[2]) + window_ms - now) end
    return {0, wait_ms, 'window'}
end

local current_delay = tonumber(redis.call('HGET', state_key, 'delay_ms') or base_delay_ms)
local effective_delay = math.max(0, math.floor(current_delay * jitter_multiplier))
local last_ms = tonumber(redis.call('HGET', state_key, 'last_ms') or '0')
local delay_wait = last_ms + effective_delay - now
if delay_wait > 0 then return {0, delay_wait, 'delay'} end

redis.call('ZADD', window_key, now, member)
redis.call('HSET', state_key, 'last_ms', now, 'delay_ms', current_delay, 'circuit', circuit)
if circuit == 'half_open' then
    redis.call('HSET', state_key, 'half_open_until', now + recovery_ms)
end
redis.call('PEXPIRE', state_key, state_ttl)
redis.call('PEXPIRE', window_key, state_ttl)
return {1, 0, circuit}
"""


_SUCCESS_SCRIPT = r"""
local state_key = KEYS[1]
local base_delay = tonumber(ARGV[1])
local adaptive = tonumber(ARGV[2])
local state_ttl = tonumber(ARGV[3])
local current_delay = tonumber(redis.call('HGET', state_key, 'delay_ms') or base_delay)
if adaptive == 1 and current_delay > base_delay then
    current_delay = math.max(base_delay, math.floor(current_delay / 2))
end
redis.call('HSET', state_key, 'errors', 0, 'circuit', 'closed',
    'opened_ms', 0, 'half_open_until', 0, 'retry_ms', 0,
    'delay_ms', current_delay)
redis.call('PEXPIRE', state_key, state_ttl)
return {current_delay, 0, 'closed'}
"""


_ERROR_SCRIPT = r"""
local state_key = KEYS[1]
local t = redis.call('TIME')
local now = (tonumber(t[1]) * 1000) + math.floor(tonumber(t[2]) / 1000)
local is_rate_limit = tonumber(ARGV[1])
local retry_after_ms = tonumber(ARGV[2])
local adaptive = tonumber(ARGV[3])
local multiplier = tonumber(ARGV[4])
local max_delay = tonumber(ARGV[5])
local base_delay = tonumber(ARGV[6])
local circuit_enabled = tonumber(ARGV[7])
local threshold = tonumber(ARGV[8])
local state_ttl = tonumber(ARGV[9])

local errors = tonumber(redis.call('HINCRBY', state_key, 'errors', 1))
local current_delay = tonumber(redis.call('HGET', state_key, 'delay_ms') or base_delay)
if adaptive == 1 and (is_rate_limit == 1 or errors >= 3) then
    current_delay = math.min(max_delay,
        math.max(base_delay, math.floor(current_delay * multiplier)))
end
local retry_ms = tonumber(redis.call('HGET', state_key, 'retry_ms') or '0')
if retry_after_ms > 0 then retry_ms = math.max(retry_ms, now + retry_after_ms) end
local circuit = redis.call('HGET', state_key, 'circuit') or 'closed'
local opened_ms = tonumber(redis.call('HGET', state_key, 'opened_ms') or '0')
if circuit_enabled == 1 and errors >= threshold then
    circuit = 'open'
    opened_ms = now
end
redis.call('HSET', state_key, 'delay_ms', current_delay, 'retry_ms', retry_ms,
    'circuit', circuit, 'opened_ms', opened_ms, 'half_open_until', 0)
redis.call('PEXPIRE', state_key, state_ttl)
return {current_delay, errors, circuit}
"""


_T = TypeVar("_T")


class RateLimiter:
    """Coordinate target request budgets across threads and processes."""

    WINDOW_SECONDS = 60.0
    STATE_TTL_MS = 3_600_000

    def __init__(
        self,
        redis_client: Any | None = None,
        *,
        use_redis: bool | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        wall_time: Callable[[], float] = time.time,
        fallback_worker_estimate: int | None = None,
    ):
        self._buckets: dict[str, _HostBucket] = {}
        self._global_lock = threading.Lock()
        self._redis_lock = threading.Lock()
        self._redis = redis_client
        self._redis_explicit = redis_client is not None
        configured = bool(str(getattr(settings, "REDIS_URL", "") or "").strip())
        shared_enabled = bool(
            getattr(settings, "RATE_LIMIT_REDIS_ENABLED", True)
        )
        self._redis_enabled = configured and shared_enabled if use_redis is None else use_redis
        self._redis_unavailable_until = 0.0
        self._redis_error: str | None = None
        self._sleep = sleeper
        self._monotonic = monotonic
        self._wall_time = wall_time
        self._fallback_worker_estimate_override = fallback_worker_estimate

    @staticmethod
    def _host_from_url(url: str) -> str:
        try:
            return urlparse(url).hostname or "unknown"
        except Exception:
            return "unknown"

    @staticmethod
    def _target_identity(url: str) -> str:
        """Return a stable per-origin identity; ports remain isolated targets."""
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            hostname = (parsed.hostname or "").encode("idna").decode("ascii").lower()
            if scheme not in {"http", "https"} or not hostname:
                return "unknown"
            default_port = 443 if scheme == "https" else 80
            return f"{scheme}://{hostname}:{parsed.port or default_port}"
        except Exception:
            return "unknown"

    @staticmethod
    def _redis_keys(identity: str) -> tuple[str, str]:
        digest = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()[:32]
        prefix = f"xssboss:target-rate:{{{digest}}}"
        return f"{prefix}:state", f"{prefix}:window"

    def _get_bucket(self, identity: str) -> _HostBucket:
        bucket = self._buckets.get(identity)
        if bucket is None:
            with self._global_lock:
                bucket = self._buckets.get(identity)
                if bucket is None:
                    bucket = _HostBucket(int(settings.REQUEST_DELAY_MS))
                    self._buckets[identity] = bucket
        return bucket

    @contextmanager
    def request_budget(self, max_requests: int):
        """Count target slots for one bounded stage, including copied contexts."""
        meter = RequestBudgetMeter(limit=max(0, int(max_requests)))
        token = _active_request_budget.set(meter)
        try:
            yield meter
        finally:
            _active_request_budget.reset(token)

    def _jitter_multiplier(self) -> float:
        jitter = max(0.0, min(float(settings.JITTER_FACTOR), 0.95))
        return random.uniform(1.0 - jitter, 1.0 + jitter) if jitter else 1.0

    def _fallback_worker_estimate(self) -> int:
        if self._fallback_worker_estimate_override is not None:
            return max(1, self._fallback_worker_estimate_override)
        configured = getattr(settings, "RATE_LIMIT_FALLBACK_WORKER_ESTIMATE", None)
        if configured is not None:
            try:
                return max(1, int(configured))
            except (TypeError, ValueError):
                pass
        return max(1,
            int(getattr(settings, "MAX_QUEUE_ACTIVE", 1))
            + int(getattr(settings, "MAX_PROFILING_WORKERS", 1))
            + int(getattr(settings, "BROWSER_WORKER_CONCURRENCY", 1)))

    def _fallback_limit(self) -> int:
        return max(1,
            int(settings.MAX_REQUESTS_PER_MINUTE) // self._fallback_worker_estimate())

    def _get_redis(self) -> Any:
        now = self._monotonic()
        if not self._redis_enabled or now < self._redis_unavailable_until:
            raise ConnectionError("shared rate-limit backend unavailable")
        if self._redis is not None:
            return self._redis
        with self._redis_lock:
            if self._redis is None:
                from redis import Redis
                self._redis = Redis.from_url(
                    settings.REDIS_URL, decode_responses=True,
                    socket_connect_timeout=0.5, socket_timeout=1.0,
                    health_check_interval=30)
        return self._redis

    def _mark_redis_failed(self, error: Exception) -> None:
        cooldown = max(
            1.0,
            float(getattr(settings, "RATE_LIMIT_REDIS_RETRY_SECS", 30.0)),
        )
        first_failure = self._redis_error is None
        self._redis_error = type(error).__name__
        self._redis_unavailable_until = self._monotonic() + cooldown
        if not self._redis_explicit:
            self._redis = None
        if first_failure:
            logger.warning(
                "[RateLimiter] Redis coordination unavailable; using conservative "
                "local allowance (%s request(s)/minute per process)",
                self._fallback_limit())

    def _redis_eval(self, script: str, keys: tuple[str, ...], args: tuple[Any, ...]) -> Any:
        try:
            result = self._get_redis().eval(script, len(keys), *keys, *args)
            self._redis_error = None
            return result
        except Exception as error:
            self._mark_redis_failed(error)
            raise

    @staticmethod
    def _decode(value: Any) -> str:
        return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)

    def _reserve_redis(self, identity: str) -> _ReservationDecision:
        result = self._redis_eval(
            _RESERVE_SCRIPT, self._redis_keys(identity),
            (int(self.WINDOW_SECONDS * 1000),
             max(1, int(settings.MAX_REQUESTS_PER_MINUTE)),
             max(0, int(settings.REQUEST_DELAY_MS)), self._jitter_multiplier(),
             int(bool(settings.CIRCUIT_BREAKER_ENABLED)),
             max(1, int(settings.CIRCUIT_BREAKER_RECOVERY_SECS * 1000)),
             uuid.uuid4().hex, self.STATE_TTL_MS))
        reason = self._decode(result[2])
        return _ReservationDecision(
            bool(int(result[0])), max(0.0, float(result[1]) / 1000.0),
            reason == "circuit_open")

    def _reserve_local(self, identity: str) -> _ReservationDecision:
        bucket = self._get_bucket(identity)
        now = self._monotonic()
        with bucket.lock:
            if settings.CIRCUIT_BREAKER_ENABLED:
                if bucket.circuit_state == CircuitState.OPEN:
                    remaining = float(settings.CIRCUIT_BREAKER_RECOVERY_SECS) - (
                        now - bucket.circuit_opened_at)
                    if remaining > 0:
                        return _ReservationDecision(False, remaining, True)
                    bucket.circuit_state = CircuitState.HALF_OPEN
                    bucket.half_open_in_flight = False
                if (bucket.circuit_state == CircuitState.HALF_OPEN
                        and bucket.half_open_in_flight
                        and bucket.half_open_until > now):
                    return _ReservationDecision(False,
                        bucket.half_open_until - now, True)

            if bucket.retry_after_until > now:
                return _ReservationDecision(False, bucket.retry_after_until - now)

            while (bucket.timestamps
                   and bucket.timestamps[0] <= now - self.WINDOW_SECONDS):
                bucket.timestamps.popleft()
            limit = (self._fallback_limit() if self._redis_enabled else
                     max(1, int(settings.MAX_REQUESTS_PER_MINUTE)))
            if len(bucket.timestamps) >= limit:
                return _ReservationDecision(False,
                    max(0.001, bucket.timestamps[0] + self.WINDOW_SECONDS - now))

            effective_delay = ((bucket.current_delay_ms / 1000.0)
                               * self._jitter_multiplier())
            delay_wait = bucket.last_request_at + effective_delay - now
            if bucket.last_request_at and delay_wait > 0:
                return _ReservationDecision(False, delay_wait)

            bucket.last_request_at = now
            bucket.timestamps.append(now)
            if bucket.circuit_state == CircuitState.HALF_OPEN:
                bucket.half_open_in_flight = True
                bucket.half_open_until = (
                    now + float(settings.CIRCUIT_BREAKER_RECOVERY_SECS))
            return _ReservationDecision(True)

    def wait_for_slot(self, url: str) -> float:
        """Atomically reserve and wait for one outbound request slot."""
        identity = self._target_identity(url)
        waited = 0.0
        while True:
            if self._redis_enabled and self._monotonic() >= self._redis_unavailable_until:
                try:
                    decision = self._reserve_redis(identity)
                except Exception as error:
                    if getattr(settings, "RATE_LIMIT_REDIS_REQUIRED", False):
                        raise CircuitOpenError(
                            "Shared rate-limit backend unavailable; outbound request refused"
                        ) from error
                    decision = self._reserve_local(identity)
            else:
                if self._redis_enabled and getattr(
                    settings, "RATE_LIMIT_REDIS_REQUIRED", False
                ):
                    raise CircuitOpenError(
                        "Shared rate-limit backend unavailable; outbound request refused"
                    )
                decision = self._reserve_local(identity)
            if decision.allowed:
                meter = _active_request_budget.get()
                if meter is not None:
                    meter.reserve()
                return waited
            if decision.circuit_open:
                raise CircuitOpenError(
                    f"Circuit breaker OPEN for {identity}; retry in "
                    f"{decision.wait_seconds:.1f}s")
            sleep_seconds = max(0.001, decision.wait_seconds)
            self._sleep(sleep_seconds)
            waited += sleep_seconds

    def _report_success_local(self, identity: str) -> None:
        bucket = self._get_bucket(identity)
        with bucket.lock:
            bucket.consecutive_errors = 0
            bucket.circuit_state = CircuitState.CLOSED
            bucket.circuit_opened_at = 0.0
            bucket.half_open_in_flight = False
            bucket.half_open_until = 0.0
            bucket.retry_after_until = 0.0
            if settings.ADAPTIVE_THROTTLE:
                base = max(0, int(settings.REQUEST_DELAY_MS))
                bucket.current_delay_ms = max(base, bucket.current_delay_ms // 2)

    def report_success(self, url: str) -> None:
        identity = self._target_identity(url)
        if self._redis_enabled and self._monotonic() >= self._redis_unavailable_until:
            try:
                self._redis_eval(_SUCCESS_SCRIPT, (self._redis_keys(identity)[0],),
                    (max(0, int(settings.REQUEST_DELAY_MS)),
                     int(bool(settings.ADAPTIVE_THROTTLE)), self.STATE_TTL_MS))
                return
            except Exception:
                pass
        self._report_success_local(identity)

    def _report_error_local(self, identity: str, is_rate_limit: bool,
                            retry_after_secs: float | None) -> None:
        bucket = self._get_bucket(identity)
        with bucket.lock:
            bucket.consecutive_errors += 1
            if retry_after_secs and retry_after_secs > 0:
                bucket.retry_after_until = max(
                    bucket.retry_after_until, self._monotonic() + retry_after_secs)
            if (settings.CIRCUIT_BREAKER_ENABLED
                    and bucket.consecutive_errors >= int(settings.CIRCUIT_BREAKER_THRESHOLD)):
                bucket.circuit_state = CircuitState.OPEN
                bucket.circuit_opened_at = self._monotonic()
                bucket.half_open_in_flight = False
            if settings.ADAPTIVE_THROTTLE and (
                    is_rate_limit or bucket.consecutive_errors >= 3):
                bucket.current_delay_ms = min(
                    int(settings.THROTTLE_MAX_DELAY_MS),
                    max(int(settings.REQUEST_DELAY_MS),
                        int(bucket.current_delay_ms
                            * float(settings.THROTTLE_BACKOFF_MULTIPLIER))))

    def report_error(self, url: str, is_rate_limit: bool = False,
                     retry_after_secs: float | None = None) -> None:
        identity = self._target_identity(url)
        retry_after_secs = (max(0.0, min(float(retry_after_secs), 86_400.0))
                            if retry_after_secs is not None else None)
        if self._redis_enabled and self._monotonic() >= self._redis_unavailable_until:
            try:
                self._redis_eval(_ERROR_SCRIPT, (self._redis_keys(identity)[0],),
                    (int(bool(is_rate_limit)), int((retry_after_secs or 0.0) * 1000),
                     int(bool(settings.ADAPTIVE_THROTTLE)),
                     max(1.0, float(settings.THROTTLE_BACKOFF_MULTIPLIER)),
                     max(0, int(settings.THROTTLE_MAX_DELAY_MS)),
                     max(0, int(settings.REQUEST_DELAY_MS)),
                     int(bool(settings.CIRCUIT_BREAKER_ENABLED)),
                     max(1, int(settings.CIRCUIT_BREAKER_THRESHOLD)),
                     self.STATE_TTL_MS))
                return
            except Exception:
                pass
        self._report_error_local(identity, is_rate_limit, retry_after_secs)

    def _retry_after_seconds(self, value: str | None) -> float | None:
        if not value:
            return None
        try:
            return max(0.0, min(float(value.strip()), 86_400.0))
        except (TypeError, ValueError):
            try:
                parsed = parsedate_to_datetime(value)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return max(0.0,
                    min(parsed.timestamp() - self._wall_time(), 86_400.0))
            except (TypeError, ValueError, OverflowError):
                return None

    def report_response(self, url: str, response: Any) -> None:
        """Update shared adaptive state from an HTTP response."""
        status_code = int(getattr(response, "status_code", 0) or 0)
        headers = getattr(response, "headers", {}) or {}
        retry_after = self._retry_after_seconds(
            headers.get("Retry-After") or headers.get("retry-after"))
        if status_code in {403, 429, 503}:
            self.report_error(url, is_rate_limit=True, retry_after_secs=retry_after)
        elif status_code >= 500 or status_code == 0:
            self.report_error(url)
        else:
            self.report_success(url)

    def get_status(self, url: str) -> dict[str, Any]:
        identity = self._target_identity(url)
        host = self._host_from_url(url)
        if self._redis_enabled and self._monotonic() >= self._redis_unavailable_until:
            try:
                client = self._get_redis()
                state_key, window_key = self._redis_keys(identity)
                cutoff_ms = int(self._wall_time() * 1000 - self.WINDOW_SECONDS * 1000)
                pipeline = client.pipeline()
                pipeline.hgetall(state_key)
                pipeline.zremrangebyscore(window_key, "-inf", cutoff_ms)
                pipeline.zcard(window_key)
                state, _, count = pipeline.execute()
                decoded = {self._decode(k): self._decode(v) for k, v in state.items()}
                return {
                    "host": host, "target_origin": identity, "backend": "redis",
                    "current_delay_ms": int(float(decoded.get(
                        "delay_ms", settings.REQUEST_DELAY_MS))),
                    "base_delay_ms": int(settings.REQUEST_DELAY_MS),
                    "requests_last_minute": int(count),
                    "max_requests_per_minute": int(settings.MAX_REQUESTS_PER_MINUTE),
                    "consecutive_errors": int(float(decoded.get("errors", 0))),
                    "adaptive_throttle": bool(settings.ADAPTIVE_THROTTLE),
                    "jitter_factor": float(settings.JITTER_FACTOR),
                    "circuit_state": decoded.get("circuit", "closed"),
                }
            except Exception as error:
                self._mark_redis_failed(error)

        bucket = self._get_bucket(identity)
        with bucket.lock:
            now = self._monotonic()
            while (bucket.timestamps
                   and bucket.timestamps[0] <= now - self.WINDOW_SECONDS):
                bucket.timestamps.popleft()
            remaining = 0.0
            if bucket.circuit_state == CircuitState.OPEN:
                remaining = max(0.0,
                    float(settings.CIRCUIT_BREAKER_RECOVERY_SECS)
                    - (now - bucket.circuit_opened_at))
            return {
                "host": host, "target_origin": identity,
                "backend": "local_fallback" if self._redis_enabled else "local",
                "backend_error": self._redis_error,
                "current_delay_ms": bucket.current_delay_ms,
                "base_delay_ms": int(settings.REQUEST_DELAY_MS),
                "requests_last_minute": len(bucket.timestamps),
                "max_requests_per_minute": (self._fallback_limit()
                    if self._redis_enabled else int(settings.MAX_REQUESTS_PER_MINUTE)),
                "configured_shared_limit": int(settings.MAX_REQUESTS_PER_MINUTE),
                "consecutive_errors": bucket.consecutive_errors,
                "adaptive_throttle": bool(settings.ADAPTIVE_THROTTLE),
                "jitter_factor": float(settings.JITTER_FACTOR),
                "circuit_state": bucket.circuit_state.value,
                "circuit_recovery_secs": round(remaining, 1),
            }

    def reset(self, url: str | None = None) -> None:
        identity = self._target_identity(url) if url else None
        if self._redis_enabled and self._monotonic() >= self._redis_unavailable_until:
            try:
                if identity:
                    self._get_redis().delete(*self._redis_keys(identity))
                else:
                    logger.debug("Shared rate limiter requires a target URL for reset")
            except Exception as error:
                self._mark_redis_failed(error)
        with self._global_lock:
            if identity:
                self._buckets.pop(identity, None)
            else:
                self._buckets.clear()


def rate_limited_call(url: str, request: Callable[[], _T]) -> _T:
    """Reserve a slot, perform one outbound request, and account its result."""
    rate_limiter.wait_for_slot(url)
    try:
        response = request()
    except CircuitOpenError:
        raise
    except Exception:
        rate_limiter.report_error(url)
        raise
    rate_limiter.report_response(url, response)
    return response


rate_limiter = RateLimiter()
