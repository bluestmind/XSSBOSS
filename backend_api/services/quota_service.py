"""Atomic per-tenant API quotas backed by Redis."""
import time

from redis import Redis

from backend_api.config import settings


class QuotaService:
    DEFAULT_REQUESTS_PER_MINUTE = 6000

    @staticmethod
    def allow_request(tenant) -> tuple[bool, int, int]:
        quotas = tenant.quotas if isinstance(tenant.quotas, dict) else {}
        limit = int(quotas.get("api_requests_per_minute", QuotaService.DEFAULT_REQUESTS_PER_MINUTE))
        if limit <= 0:
            return False, 0, limit
        minute = int(time.time() // 60)
        key = f"xssboss:quota:{tenant.id}:{minute}"
        client = Redis.from_url(settings.REDIS_URL)
        pipeline = client.pipeline()
        pipeline.incr(key)
        pipeline.expire(key, 120)
        count, _ = pipeline.execute()
        return count <= limit, int(count), limit
