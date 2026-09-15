"""Bounded GET-only HTTP acquisition with manual redirect validation."""

from __future__ import annotations

import asyncio
import socket
import time
import urllib.error
import urllib.request
from collections import defaultdict
from urllib.parse import urlsplit

from .config import CrawlConfig
from .models import FetchResult, RequestRecord
from .scope import ScopePolicy


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class HTTPCollector:
    def __init__(self, config: CrawlConfig, scope: ScopePolicy):
        self.config = config
        self.scope = scope
        self._global = asyncio.Semaphore(config.concurrency)
        self._hosts: dict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(config.per_host_concurrency))
        self._rate_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        self._last_request: dict[str, float] = defaultdict(float)

    async def fetch(self, url: str) -> FetchResult:
        current = url
        redirect_count = 0
        while True:
            result = await self._fetch_once(current)
            location = next((value for key, value in result.headers.items() if key.lower() == "location"), None)
            if not (self.config.follow_redirects and location and result.status in {301, 302, 303, 307, 308}):
                result.final_url = current
                return result
            if redirect_count >= 10:
                result.error = "redirect limit exceeded"
                return result
            from urllib.parse import urljoin
            destination = urljoin(current, location)
            if not self.scope.is_allowed(destination):
                result.error = f"redirect blocked by scope policy: {destination}"
                return result
            current = destination
            redirect_count += 1

    async def _fetch_once(self, url: str) -> FetchResult:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        request = RequestRecord(method="GET", url=url, source="live")
        try:
            await asyncio.to_thread(self.scope.validate_destination, url)
        except Exception as exc:
            return FetchResult(request, url, 0, {}, b"", 0.0, error=str(exc))
        async with self._global, self._hosts[host]:
            async with self._rate_locks[host]:
                interval = 1.0 / self.config.requests_per_second
                delay = interval - (time.monotonic() - self._last_request[host])
                if delay > 0:
                    await asyncio.sleep(delay)
                self._last_request[host] = time.monotonic()
            last: FetchResult | None = None
            for attempt in range(self.config.retries + 1):
                last = await asyncio.to_thread(self._blocking_fetch, request)
                if not last.error or last.status in {400, 401, 403, 404, 405, 410, 422}:
                    return last
                if attempt < self.config.retries:
                    await asyncio.sleep(min(4.0, 0.4 * (2 ** attempt)))
            return last or FetchResult(request, url, 0, {}, b"", 0.0, error="unknown fetch failure")

    def _blocking_fetch(self, request: RequestRecord) -> FetchResult:
        started = time.perf_counter()
        req = urllib.request.Request(
            request.url,
            method="GET",
            headers={"User-Agent": self.config.user_agent, "Accept": "*/*", "Accept-Encoding": "identity"},
        )
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(req, timeout=self.config.timeout_seconds) as response:
                body = response.read(self.config.max_response_bytes + 1)
                truncated = len(body) > self.config.max_response_bytes
                body = body[:self.config.max_response_bytes]
                return FetchResult(request, request.url, int(response.status), dict(response.headers.items()), body,
                                   (time.perf_counter() - started) * 1000, truncated=truncated)
        except urllib.error.HTTPError as exc:
            body = exc.read(self.config.max_response_bytes + 1)
            truncated = len(body) > self.config.max_response_bytes
            return FetchResult(request, request.url, int(exc.code), dict(exc.headers.items()),
                               body[:self.config.max_response_bytes], (time.perf_counter() - started) * 1000,
                               truncated=truncated)
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
            return FetchResult(request, request.url, 0, {}, b"", (time.perf_counter() - started) * 1000,
                               error=f"{type(exc).__name__}: {exc}")

