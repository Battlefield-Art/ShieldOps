"""Behavioral tests for RateLimitMiddleware — fixed-window Redis rate limiter."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI

from shieldops.api.middleware.rate_limiter import RateLimitMiddleware

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_app() -> FastAPI:
    """Minimal FastAPI app with the rate-limit middleware attached."""
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/ready")
    async def ready():
        return {"status": "ready"}

    @app.get("/metrics")
    async def metrics():
        return {"metrics": []}

    @app.get("/api/v1/docs")
    async def docs():
        return {"docs": True}

    @app.get("/api/v1/openapi.json")
    async def openapi():
        return {}

    @app.get("/api/v1/redoc")
    async def redoc():
        return {"redoc": True}

    @app.post("/api/v1/auth/login")
    async def login():
        return {"token": "tok"}

    @app.post("/api/v1/auth/register")
    async def register():
        return {"created": True}

    @app.get("/api/v1/agents")
    async def agents():
        return {"agents": []}

    @app.get("/api/v1/investigations")
    async def investigations():
        return {"investigations": []}

    return app


def _make_redis_mock(current_count: int = 1) -> AsyncMock:
    """Return an AsyncMock Redis client whose INCR returns *current_count*."""
    redis = AsyncMock()
    redis.incr = AsyncMock(return_value=current_count)
    redis.expire = AsyncMock(return_value=True)
    return redis


def _settings_defaults(**overrides):
    """Patch target for the settings object used by the middleware module."""
    defaults = {
        "rate_limit_enabled": True,
        "rate_limit_window_seconds": 60,
        "rate_limit_admin": 300,
        "rate_limit_operator": 120,
        "rate_limit_viewer": 60,
        "rate_limit_default": 60,
        "rate_limit_auth_login": 10,
        "rate_limit_auth_register": 5,
        "api_prefix": "/api/v1",
        "redis_url": "redis://localhost:6379/0",
    }
    defaults.update(overrides)
    mock = MagicMock()
    for k, v in defaults.items():
        setattr(mock, k, v)
    return mock


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def app() -> FastAPI:
    return _build_app()


@pytest.fixture()
def redis_mock() -> AsyncMock:
    return _make_redis_mock(current_count=1)


# ---------------------------------------------------------------------------
# Tests — Exempt paths
# ---------------------------------------------------------------------------


class TestExemptPaths:
    """Paths like /health, /ready, /metrics should bypass rate limiting entirely."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "path",
        [
            "/health",
            "/ready",
            "/metrics",
            "/api/v1/docs",
            "/api/v1/openapi.json",
            "/api/v1/redoc",
        ],
    )
    async def test_exempt_path_has_no_rate_limit_headers(self, app, redis_mock, path):
        # Arrange — middleware should never touch Redis for exempt paths
        with patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                # Act
                resp = await client.get(path)

        # Assert
        assert resp.status_code == 200
        assert "X-RateLimit-Limit" not in resp.headers
        assert "X-RateLimit-Remaining" not in resp.headers
        redis_mock.incr.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_exempt_path_gets_rate_limit_headers(self, app, redis_mock):
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/agents")

        assert resp.status_code == 200
        assert "X-RateLimit-Limit" in resp.headers


# ---------------------------------------------------------------------------
# Tests — Rate limit behavior
# ---------------------------------------------------------------------------


class TestRateLimitBehavior:
    """Core rate-limiting logic: role-based limits, 429 responses, headers."""

    @pytest.mark.asyncio
    async def test_unauthenticated_request_gets_default_limit(self, app, redis_mock):
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/agents")

        assert resp.status_code == 200
        assert resp.headers["X-RateLimit-Limit"] == "60"
        remaining = int(resp.headers["X-RateLimit-Remaining"])
        assert remaining == 59  # 60 - 1

    @pytest.mark.asyncio
    async def test_authenticated_admin_gets_300_limit(self, app, redis_mock):
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=("user-admin-1", "admin"),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/agents")

        assert resp.status_code == 200
        assert resp.headers["X-RateLimit-Limit"] == "300"
        assert resp.headers["X-RateLimit-Remaining"] == "299"

    @pytest.mark.asyncio
    async def test_authenticated_operator_gets_120_limit(self, app, redis_mock):
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=("user-op-1", "operator"),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/agents")

        assert resp.status_code == 200
        assert resp.headers["X-RateLimit-Limit"] == "120"

    @pytest.mark.asyncio
    async def test_authenticated_viewer_gets_60_limit(self, app, redis_mock):
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=("user-viewer-1", "viewer"),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/agents")

        assert resp.status_code == 200
        assert resp.headers["X-RateLimit-Limit"] == "60"

    @pytest.mark.asyncio
    async def test_over_limit_returns_429_with_headers(self, app):
        # Arrange — Redis returns count > limit (61 > 60 for unauthenticated)
        redis_over = _make_redis_mock(current_count=61)

        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_over),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/agents")

        assert resp.status_code == 429
        body = resp.json()
        assert body["detail"] == "Rate limit exceeded"
        assert "retry_after" in body

        # Headers must be present on 429 responses
        assert resp.headers["X-RateLimit-Limit"] == "60"
        assert resp.headers["X-RateLimit-Remaining"] == "0"
        assert "X-RateLimit-Reset" in resp.headers
        assert "Retry-After" in resp.headers

    @pytest.mark.asyncio
    async def test_at_exact_limit_still_allowed(self, app):
        """Count == limit is NOT over limit (only count > limit is)."""
        redis_at_limit = _make_redis_mock(current_count=60)

        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_at_limit),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/agents")

        assert resp.status_code == 200
        assert resp.headers["X-RateLimit-Remaining"] == "0"

    @pytest.mark.asyncio
    async def test_normal_response_includes_rate_limit_headers(self, app, redis_mock):
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/agents")

        assert resp.status_code == 200
        assert "X-RateLimit-Limit" in resp.headers
        assert "X-RateLimit-Remaining" in resp.headers
        assert "X-RateLimit-Reset" in resp.headers

    @pytest.mark.asyncio
    async def test_redis_expire_called_on_first_request(self, app, redis_mock):
        """When INCR returns 1, EXPIRE must be set to establish the window."""
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                await client.get("/api/v1/agents")

        redis_mock.expire.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_redis_expire_not_called_on_subsequent_requests(self, app):
        """When INCR returns > 1, EXPIRE should NOT be called again."""
        redis_second = _make_redis_mock(current_count=5)

        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_second),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                await client.get("/api/v1/agents")

        redis_second.expire.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_auth_login_uses_stricter_ip_limit(self, app, redis_mock):
        """Auth login endpoint should use rate_limit_auth_login (10) not default."""
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/v1/auth/login")

        assert resp.headers["X-RateLimit-Limit"] == "10"

    @pytest.mark.asyncio
    async def test_auth_register_uses_stricter_limit(self, app, redis_mock):
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/v1/auth/register")

        assert resp.headers["X-RateLimit-Limit"] == "5"

    @pytest.mark.asyncio
    async def test_auth_endpoint_over_limit_returns_429(self, app):
        redis_over = _make_redis_mock(current_count=11)

        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_over),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/v1/auth/login")

        assert resp.status_code == 429
        assert resp.headers["X-RateLimit-Limit"] == "10"

    @pytest.mark.asyncio
    async def test_unknown_role_falls_back_to_default_limit(self, app, redis_mock):
        """An authenticated user with an unrecognised role gets the default limit."""
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=("user-x", "custom_role"),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/agents")

        assert resp.status_code == 200
        assert resp.headers["X-RateLimit-Limit"] == "60"


# ---------------------------------------------------------------------------
# Tests — Fail-open on Redis errors
# ---------------------------------------------------------------------------


class TestFailOpen:
    """When Redis is unavailable the middleware must fail-open."""

    @pytest.mark.asyncio
    async def test_redis_connection_error_allows_request(self, app):
        redis_broken = AsyncMock()
        redis_broken.incr = AsyncMock(side_effect=ConnectionError("Redis is down"))

        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_broken),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/agents")

        # Request should succeed (fail-open)
        assert resp.status_code == 200
        # No rate-limit headers because Redis failed before we got a count
        assert "X-RateLimit-Limit" not in resp.headers

    @pytest.mark.asyncio
    async def test_redis_timeout_allows_request(self, app):
        redis_slow = AsyncMock()
        redis_slow.incr = AsyncMock(side_effect=TimeoutError("Redis timeout"))

        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_slow),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/agents")

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_redis_generic_exception_allows_request(self, app):
        redis_broken = AsyncMock()
        redis_broken.incr = AsyncMock(side_effect=RuntimeError("unexpected"))

        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_broken),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/agents")

        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Tests — Disabled rate limiting
# ---------------------------------------------------------------------------


class TestRateLimitDisabled:
    """When settings.rate_limit_enabled is False, middleware is a no-op."""

    @pytest.mark.asyncio
    async def test_disabled_rate_limit_passes_through(self, app):
        with patch("shieldops.api.middleware.rate_limiter.settings") as mock_settings:
            mock_settings.rate_limit_enabled = False
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/agents")

        assert resp.status_code == 200
        assert "X-RateLimit-Limit" not in resp.headers


# ---------------------------------------------------------------------------
# Tests — Client IP extraction
# ---------------------------------------------------------------------------


class TestClientIpExtraction:
    """_get_client_ip should prefer X-Forwarded-For, fall back to client.host."""

    @pytest.mark.asyncio
    async def test_x_forwarded_for_first_hop_used(self, app, redis_mock):
        """The first IP in X-Forwarded-For should be used for the rate-limit key."""
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get(
                    "/api/v1/agents",
                    headers={"X-Forwarded-For": "203.0.113.50, 10.0.0.1"},
                )

        assert resp.status_code == 200
        # Verify the Redis key contains the first-hop IP
        incr_call = redis_mock.incr.call_args
        redis_key = incr_call[0][0]
        assert "ip:203.0.113.50" in redis_key

    @pytest.mark.asyncio
    async def test_single_x_forwarded_for_ip(self, app, redis_mock):
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                await client.get(
                    "/api/v1/agents",
                    headers={"X-Forwarded-For": "198.51.100.1"},
                )

        redis_key = redis_mock.incr.call_args[0][0]
        assert "ip:198.51.100.1" in redis_key

    @pytest.mark.asyncio
    async def test_no_x_forwarded_for_uses_client_host(self, app, redis_mock):
        """Without X-Forwarded-For, client.host (from the transport) is used."""
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/v1/agents")

        assert resp.status_code == 200
        redis_key = redis_mock.incr.call_args[0][0]
        # httpx ASGITransport uses "127.0.0.1" as default client host
        assert "ip:" in redis_key

    @pytest.mark.asyncio
    async def test_authenticated_user_keyed_by_user_id(self, app, redis_mock):
        """Authenticated users should be keyed by user:<id>, not IP."""
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=("usr_abc123", "admin"),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                await client.get("/api/v1/agents")

        redis_key = redis_mock.incr.call_args[0][0]
        assert "user:usr_abc123" in redis_key
        assert "ip:" not in redis_key

    @pytest.mark.asyncio
    async def test_auth_endpoint_keyed_by_ip_and_path(self, app, redis_mock):
        """Auth endpoints always use IP-based keys regardless of auth status."""
        with (
            patch.object(RateLimitMiddleware, "_ensure_client", return_value=redis_mock),
            patch(
                "shieldops.api.middleware.rate_limiter._extract_user",
                return_value=(None, None),
            ),
        ):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                await client.post(
                    "/api/v1/auth/login",
                    headers={"X-Forwarded-For": "10.0.0.55"},
                )

        redis_key = redis_mock.incr.call_args[0][0]
        assert "ip:10.0.0.55" in redis_key
        assert "/api/v1/auth/login" in redis_key
