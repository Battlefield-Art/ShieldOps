"""Per-organisation ingestion rate limiter based on daily byte volume.

Tier limits (bytes/day):
  - starter:      5 GB
  - professional: 50 GB
  - enterprise:   500 GB
  - self_hosted:  unlimited (no enforcement)

Uses Redis sliding-window counters keyed by ``org_id + date``.
Falls open (allows traffic) when Redis is unavailable — ingestion
availability is preferred over strict enforcement.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

logger = structlog.get_logger()

# Tier → daily byte allowance
TIER_BYTE_LIMITS: dict[str, int] = {
    "starter": 5 * 1024**3,  # 5 GB
    "professional": 50 * 1024**3,  # 50 GB
    "enterprise": 500 * 1024**3,  # 500 GB
    "self_hosted": 0,  # 0 = unlimited
}

_INGEST_PATH_PREFIX = "/api/v1/ingestion"


def _seconds_until_midnight_utc() -> int:
    """Seconds remaining in the current UTC day."""
    now = datetime.now(UTC)
    end_of_day = now.replace(hour=23, minute=59, second=59, microsecond=0)
    return max(1, int((end_of_day - now).total_seconds()) + 1)


class IngestionRateLimiter(BaseHTTPMiddleware):
    """Enforce per-org daily ingestion byte limits via Redis."""

    def __init__(self, app: ASGIApp, redis: Any | None = None) -> None:
        super().__init__(app)
        self._redis = redis

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Only apply to ingestion endpoints
        if not request.url.path.startswith(_INGEST_PATH_PREFIX):
            return await call_next(request)

        # Only POST requests carry ingestion payloads
        if request.method != "POST":
            return await call_next(request)

        org_id: str = getattr(request.state, "organization_id", None) or "default"
        tier: str = getattr(request.state, "tier", None) or "starter"

        # Unlimited tier — skip enforcement
        byte_limit = TIER_BYTE_LIMITS.get(tier, TIER_BYTE_LIMITS["starter"])
        if byte_limit == 0:
            return await call_next(request)

        # Estimate request body size from Content-Length header
        content_length = int(request.headers.get("content-length", "0"))

        if self._redis is None:
            logger.warning(
                "ingestion_rate_limiter_no_redis",
                org_id=org_id,
                detail="fail-open: allowing request without rate check",
            )
            return await call_next(request)

        today = datetime.now(UTC).strftime("%Y-%m-%d")
        redis_key = f"shieldops:ingest_bytes:{org_id}:{today}"

        try:
            current_bytes = await self._redis.incrby(redis_key, content_length)
            # Set TTL on first write so the key auto-expires after today
            if current_bytes == content_length:
                await self._redis.expire(redis_key, _seconds_until_midnight_utc())
        except Exception as exc:
            logger.warning(
                "ingestion_rate_limiter_redis_error",
                error=str(exc),
                org_id=org_id,
                detail="fail-open: allowing request",
            )
            return await call_next(request)

        if current_bytes > byte_limit:
            retry_after = _seconds_until_midnight_utc()
            logger.warning(
                "ingestion_rate_limit_exceeded",
                org_id=org_id,
                tier=tier,
                used_bytes=current_bytes,
                limit_bytes=byte_limit,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Ingestion rate limit exceeded",
                    "tier": tier,
                    "limit_bytes": byte_limit,
                    "used_bytes": current_bytes,
                    "retry_after": retry_after,
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(byte_limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        remaining = max(0, byte_limit - current_bytes)
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(byte_limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response
