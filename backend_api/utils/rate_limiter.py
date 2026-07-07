"""Per-target adaptive rate limiter with circuit breaker for XSS Boss.

Prevents IP bans by enforcing configurable delays between requests to
the same target host.  The limiter lives in-process and is shared across
all Celery worker threads via a module-level singleton.

Key features:
  - Configurable base delay (REQUEST_DELAY_MS).
  - Jitter: ±JITTER_FACTOR randomization on delays to avoid bot fingerprinting.
  - Hard cap on requests per minute (MAX_REQUESTS_PER_MINUTE).
  - Adaptive back-off: when a request returns a rate-limit signal
    (HTTP 429, connection timeout, WAF block page), the delay doubles
    up to THROTTLE_MAX_DELAY_MS.
  - Automatic cool-down: successive successes halve the delay back
    toward the configured base.
  - Circuit Breaker: 3-state model (CLOSED/OPEN/HALF_OPEN) that
    auto-pauses scanning when a target becomes unreachable.
  - Retry-After: respects server-provided retry delay from 429 responses.
"""

import enum
import random
import threading
import time
from collections import deque
from urllib.parse import urlparse

from backend_api.config import settings
from backend_api.utils.logger import logger


# ---------------------------------------------------------------------------
# Circuit Breaker States
# ---------------------------------------------------------------------------

class CircuitState(enum.Enum):
    CLOSED = "closed"       # Normal — requests flow
    OPEN = "open"           # Tripped — target unreachable, block all requests
    HALF_OPEN = "half_open" # Recovery probe — allow one request through


# ---------------------------------------------------------------------------
# Per-Host Bucket
# ---------------------------------------------------------------------------

class _HostBucket:
    """Track request timing, adaptive delay, and circuit breaker for a single host."""

    __slots__ = (
        "lock", "last_request_at", "current_delay_ms", "timestamps",
        "consecutive_errors", "circuit_state", "circuit_opened_at",
        "retry_after_until",
    )

    def __init__(self, base_delay_ms: int):
        self.lock = threading.Lock()
        self.last_request_at: float = 0.0
        self.current_delay_ms: int = base_delay_ms
        # Rolling window of timestamps for per-minute cap
        self.timestamps: deque = deque()
        self.consecutive_errors: int = 0
        # Circuit breaker
        self.circuit_state: CircuitState = CircuitState.CLOSED
        self.circuit_opened_at: float = 0.0
        # Retry-After support
        self.retry_after_until: float = 0.0


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Thread-safe per-host rate limiter with jitter, circuit breaker, and adaptive back-off."""

    def __init__(self):
        self._buckets: dict[str, _HostBucket] = {}
        self._global_lock = threading.Lock()

    def _get_bucket(self, host: str) -> _HostBucket:
        if host not in self._buckets:
            with self._global_lock:
                if host not in self._buckets:
                    self._buckets[host] = _HostBucket(settings.REQUEST_DELAY_MS)
        return self._buckets[host]

    @staticmethod
    def _host_from_url(url: str) -> str:
        try:
            return urlparse(url).hostname or "unknown"
        except Exception:
            return "unknown"

    @staticmethod
    def _apply_jitter(delay_s: float) -> float:
        """Add random noise to a delay to avoid bot fingerprinting."""
        jitter = settings.JITTER_FACTOR
        if jitter <= 0:
            return delay_s
        factor = random.uniform(1.0 - jitter, 1.0 + jitter)
        return max(0.05, delay_s * factor)

    # -----------------------------------------------------------------------
    # Circuit Breaker
    # -----------------------------------------------------------------------

    def _check_circuit(self, bucket: _HostBucket, host: str) -> bool:
        """Check if the circuit breaker allows a request through.

        Returns True if allowed, False if blocked (circuit OPEN).
        When the recovery period elapses, transitions to HALF_OPEN and lets one through.
        """
        if not settings.CIRCUIT_BREAKER_ENABLED:
            return True

        if bucket.circuit_state == CircuitState.CLOSED:
            return True

        if bucket.circuit_state == CircuitState.OPEN:
            elapsed = time.monotonic() - bucket.circuit_opened_at
            if elapsed >= settings.CIRCUIT_BREAKER_RECOVERY_SECS:
                bucket.circuit_state = CircuitState.HALF_OPEN
                logger.info(
                    f"[CircuitBreaker] {host}: OPEN -> HALF_OPEN after "
                    f"{elapsed:.0f}s, allowing probe request"
                )
                return True
            return False

        # HALF_OPEN — allow exactly one request through
        return True

    def _trip_circuit(self, bucket: _HostBucket, host: str):
        """Trip the circuit breaker to OPEN state."""
        if not settings.CIRCUIT_BREAKER_ENABLED:
            return
        if bucket.circuit_state != CircuitState.OPEN:
            bucket.circuit_state = CircuitState.OPEN
            bucket.circuit_opened_at = time.monotonic()
            logger.warning(
                f"[CircuitBreaker] {host}: TRIPPED -> OPEN after "
                f"{bucket.consecutive_errors} consecutive errors. "
                f"Blocking requests for {settings.CIRCUIT_BREAKER_RECOVERY_SECS}s."
            )

    def _close_circuit(self, bucket: _HostBucket, host: str):
        """Close the circuit breaker — target is healthy again."""
        if bucket.circuit_state != CircuitState.CLOSED:
            old_state = bucket.circuit_state.value
            bucket.circuit_state = CircuitState.CLOSED
            logger.info(f"[CircuitBreaker] {host}: {old_state} -> CLOSED (target healthy)")

    # -----------------------------------------------------------------------
    # Main API
    # -----------------------------------------------------------------------

    def wait_for_slot(self, url: str) -> float:
        """Block until the caller is allowed to make a request.

        Returns the number of seconds actually waited.
        Raises RuntimeError if the circuit breaker is OPEN (target down).
        """
        host = self._host_from_url(url)
        bucket = self._get_bucket(host)

        with bucket.lock:
            # --- circuit breaker check ---
            if not self._check_circuit(bucket, host):
                remaining = settings.CIRCUIT_BREAKER_RECOVERY_SECS - (
                    time.monotonic() - bucket.circuit_opened_at
                )
                raise CircuitOpenError(
                    f"Circuit breaker OPEN for {host}. "
                    f"Target appears down. Retry in {remaining:.0f}s."
                )

            now = time.monotonic()

            # --- Retry-After: server told us to wait ---
            if bucket.retry_after_until > now:
                sleep_secs = bucket.retry_after_until - now
                logger.info(
                    f"[RateLimiter] {host}: Retry-After header active, "
                    f"sleeping {sleep_secs:.1f}s"
                )
                bucket.lock.release()
                time.sleep(sleep_secs)
                bucket.lock.acquire()
                now = time.monotonic()

            # --- per-minute hard cap ---
            window_start = now - 60.0
            while bucket.timestamps and bucket.timestamps[0] < window_start:
                bucket.timestamps.popleft()

            if len(bucket.timestamps) >= settings.MAX_REQUESTS_PER_MINUTE:
                oldest = bucket.timestamps[0]
                sleep_secs = (oldest + 60.0) - now
                if sleep_secs > 0:
                    logger.info(
                        f"[RateLimiter] {host}: per-minute cap "
                        f"({settings.MAX_REQUESTS_PER_MINUTE}) reached, "
                        f"sleeping {sleep_secs:.1f}s"
                    )
                    bucket.lock.release()
                    time.sleep(sleep_secs)
                    bucket.lock.acquire()
                    now = time.monotonic()

            # --- per-request delay with jitter ---
            delay_s = bucket.current_delay_ms / 1000.0
            delay_s = self._apply_jitter(delay_s)
            elapsed = now - bucket.last_request_at
            if elapsed < delay_s:
                sleep_secs = delay_s - elapsed
                bucket.lock.release()
                time.sleep(sleep_secs)
                bucket.lock.acquire()
                now = time.monotonic()
            else:
                sleep_secs = 0.0

            bucket.last_request_at = now
            bucket.timestamps.append(now)
            return sleep_secs

    def report_success(self, url: str):
        """Call after a successful request to cool down adaptive delay."""
        if not settings.ADAPTIVE_THROTTLE:
            return

        host = self._host_from_url(url)
        bucket = self._get_bucket(host)

        with bucket.lock:
            bucket.consecutive_errors = 0

            # Close circuit breaker on success
            self._close_circuit(bucket, host)

            base = settings.REQUEST_DELAY_MS
            if bucket.current_delay_ms > base:
                new_delay = max(base, bucket.current_delay_ms // 2)
                if new_delay != bucket.current_delay_ms:
                    logger.debug(
                        f"[RateLimiter] {host}: cooling down "
                        f"{bucket.current_delay_ms}ms -> {new_delay}ms"
                    )
                    bucket.current_delay_ms = new_delay

    def report_error(self, url: str, is_rate_limit: bool = False,
                     retry_after_secs: float | None = None):
        """Call when a request fails.  Doubles delay on rate-limit signals.

        Args:
            url: The target URL.
            is_rate_limit: True if the error was a 429/WAF block.
            retry_after_secs: Value from the Retry-After response header (seconds).
        """
        if not settings.ADAPTIVE_THROTTLE:
            return

        host = self._host_from_url(url)
        bucket = self._get_bucket(host)

        with bucket.lock:
            bucket.consecutive_errors += 1

            # --- Retry-After header support ---
            if retry_after_secs and retry_after_secs > 0:
                bucket.retry_after_until = time.monotonic() + retry_after_secs
                logger.warning(
                    f"[RateLimiter] {host}: server sent Retry-After={retry_after_secs}s, "
                    f"honoring it"
                )

            # --- Circuit breaker: trip on too many consecutive failures ---
            if bucket.consecutive_errors >= settings.CIRCUIT_BREAKER_THRESHOLD:
                self._trip_circuit(bucket, host)

            # --- Adaptive backoff ---
            if is_rate_limit or bucket.consecutive_errors >= 3:
                old = bucket.current_delay_ms
                new_delay = min(
                    int(old * settings.THROTTLE_BACKOFF_MULTIPLIER),
                    settings.THROTTLE_MAX_DELAY_MS,
                )
                if new_delay != old:
                    logger.warning(
                        f"[RateLimiter] {host}: rate-limit/error detected, "
                        f"backing off {old}ms -> {new_delay}ms "
                        f"(consecutive errors: {bucket.consecutive_errors})"
                    )
                    bucket.current_delay_ms = new_delay

    def get_status(self, url: str) -> dict:
        """Return the current throttle status for a host (for UI display)."""
        host = self._host_from_url(url)
        bucket = self._get_bucket(host)
        with bucket.lock:
            now = time.monotonic()
            window_start = now - 60.0
            while bucket.timestamps and bucket.timestamps[0] < window_start:
                bucket.timestamps.popleft()
            circuit_recovery_remaining = 0.0
            if bucket.circuit_state == CircuitState.OPEN:
                circuit_recovery_remaining = max(
                    0.0,
                    settings.CIRCUIT_BREAKER_RECOVERY_SECS - (now - bucket.circuit_opened_at)
                )
            return {
                "host": host,
                "current_delay_ms": bucket.current_delay_ms,
                "base_delay_ms": settings.REQUEST_DELAY_MS,
                "requests_last_minute": len(bucket.timestamps),
                "max_requests_per_minute": settings.MAX_REQUESTS_PER_MINUTE,
                "consecutive_errors": bucket.consecutive_errors,
                "adaptive_throttle": settings.ADAPTIVE_THROTTLE,
                "jitter_factor": settings.JITTER_FACTOR,
                "circuit_state": bucket.circuit_state.value,
                "circuit_recovery_secs": round(circuit_recovery_remaining, 1),
            }

    def reset(self, url: str | None = None):
        """Reset throttle state for a host or all hosts."""
        if url:
            host = self._host_from_url(url)
            with self._global_lock:
                self._buckets.pop(host, None)
        else:
            with self._global_lock:
                self._buckets.clear()


class CircuitOpenError(RuntimeError):
    """Raised when the circuit breaker is OPEN and requests are blocked."""
    pass


# Module-level singleton shared by all worker threads
rate_limiter = RateLimiter()
