"""Wire :class:`TokenBucketMiddleware` into a FastAPI app (TDD #3-wire).

Usage in ``api/app.py``::

    from shieldops.api.middleware.token_bucket_wiring import install_token_bucket_middleware

    install_token_bucket_middleware(
        app,
        capacity=settings.rate_limit_capacity,
        refill_rate_per_sec=settings.rate_limit_refill_per_sec,
        exempt_paths=["/health", "/ready", "/metrics", "/health/deep"],
    )

Key-extraction order:
  1. ``X-API-Key`` header
  2. ``Authorization`` header (full value; includes scheme + token)
  3. Client IP
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import FastAPI
from starlette.requests import Request

from shieldops.api.middleware.token_bucket import TokenBucketMiddleware

logger = structlog.get_logger(__name__)


def _default_key_fn(exempt_paths: tuple[str, ...]) -> Any:
    def _key(request: Request) -> str:
        # Exempt paths get a special "exempt" key that will never exceed
        # (with an effectively unlimited bucket handled by the wrapper).
        path = request.url.path
        for prefix in exempt_paths:
            if path.startswith(prefix):
                return "__exempt__"
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return f"key:{api_key}"
        auth = request.headers.get("Authorization")
        if auth:
            return f"auth:{auth}"
        client = request.client
        if client and client.host:
            return f"ip:{client.host}"
        return "ip:unknown"

    return _key


class _ExemptAwareMiddleware(TokenBucketMiddleware):
    """Wraps TokenBucketMiddleware, bypassing the bucket for exempt keys."""

    async def __call__(  # type: ignore[override]
        self,
        scope: dict[str, Any],
        receive: Any,
        send: Any,
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        key = self._key_fn(Request(scope))
        if key == "__exempt__":
            await self.app(scope, receive, send)
            return
        await super().__call__(scope, receive, send)


def install_token_bucket_middleware(
    app: FastAPI,
    *,
    capacity: int,
    refill_rate_per_sec: float,
    exempt_paths: list[str] | None = None,
) -> None:
    """Install the token-bucket rate limiter on a FastAPI app."""
    exempt = tuple(exempt_paths or [])
    key_fn = _default_key_fn(exempt)
    app.add_middleware(
        _ExemptAwareMiddleware,
        capacity=capacity,
        refill_rate_per_sec=refill_rate_per_sec,
        key_fn=key_fn,
    )
    logger.info(
        "token_bucket.installed",
        capacity=capacity,
        refill_rate=refill_rate_per_sec,
        exempt_paths=list(exempt),
    )
