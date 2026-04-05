"""Tests for TenantMiddleware and IdempotencyMiddleware.

Covers tenant isolation (public paths, pre-set org_id, header fallback)
and idempotency enforcement (method filtering, cache hit/miss, TTL expiry,
composite key isolation, InMemoryIdempotencyStore semantics).
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

from shieldops.api.middleware.idempotency import (
    IdempotencyMiddleware,
    InMemoryIdempotencyStore,
)
from shieldops.api.middleware.tenant import TenantMiddleware

# ── Helpers ──────────────────────────────────────────────────────────


_call_count: int = 0


async def _ok_endpoint(request: Request) -> Response:
    """Returns 200 with the resolved organization_id."""
    org_id = getattr(request.state, "organization_id", "__MISSING__")
    return JSONResponse({"org_id": org_id, "status": "ok"})


async def _counting_endpoint(request: Request) -> Response:
    """Increments a counter on each real invocation."""
    global _call_count
    _call_count += 1
    return JSONResponse({"call_count": _call_count})


async def _plain_text_endpoint(request: Request) -> Response:
    """Returns a non-JSON response (plain text)."""
    return PlainTextResponse("not json")


class OrgSetter(BaseHTTPMiddleware):
    """Simulates upstream auth middleware that pre-sets organization_id."""

    def __init__(self, app: object, org_id: str) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._org_id = org_id

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        request.state.organization_id = self._org_id
        return await call_next(request)


def _build_tenant_app(
    *,
    pre_set_org_id: str | None = None,
) -> Starlette:
    """Build a minimal Starlette app with TenantMiddleware."""
    routes = [
        Route("/health", _ok_endpoint),
        Route("/ready", _ok_endpoint),
        Route("/metrics", _ok_endpoint),
        Route("/api/v1/docs", _ok_endpoint),
        Route("/api/v1/openapi.json", _ok_endpoint),
        Route("/api/v1/auth/login", _ok_endpoint, methods=["POST"]),
        Route("/api/v1/auth/register", _ok_endpoint, methods=["POST"]),
        Route("/api/v1/auth/oidc/login", _ok_endpoint),
        Route("/api/v1/auth/oidc/callback", _ok_endpoint),
        Route("/api/v1/agents", _ok_endpoint, methods=["GET", "POST"]),
        Route("/api/v1/investigations", _ok_endpoint),
    ]
    app = Starlette(routes=routes)
    app.add_middleware(TenantMiddleware)
    if pre_set_org_id is not None:
        app.add_middleware(OrgSetter, org_id=pre_set_org_id)
    return app


def _build_idempotency_app(
    store: InMemoryIdempotencyStore | None = None,
    ttl: int = 86400,
) -> Starlette:
    """Build a minimal Starlette app with IdempotencyMiddleware."""
    global _call_count
    _call_count = 0
    routes = [
        Route(
            "/api/v1/actions", _counting_endpoint, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]
        ),
        Route("/api/v1/text", _plain_text_endpoint, methods=["POST"]),
    ]
    app = Starlette(routes=routes)
    effective_store = store or InMemoryIdempotencyStore(ttl=ttl)
    app.add_middleware(IdempotencyMiddleware, store=effective_store, ttl=ttl)
    return app


# ── TestTenantMiddleware ─────────────────────────────────────────────


class TestTenantMiddleware:
    """Feature: Tenant isolation via organization_id on request.state."""

    @pytest.mark.parametrize(
        "path",
        [
            "/health",
            "/ready",
            "/metrics",
            "/api/v1/docs",
            "/api/v1/openapi.json",
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/oidc/login",
            "/api/v1/auth/oidc/callback",
        ],
    )
    def test_public_path_sets_org_id_to_none(self, path: str) -> None:
        """Given a request to a public path,
        When TenantMiddleware processes it,
        Then organization_id should be None."""
        client = TestClient(_build_tenant_app())
        method = "POST" if path in {"/api/v1/auth/login", "/api/v1/auth/register"} else "GET"
        resp = client.request(method, path)
        assert resp.status_code == 200
        assert resp.json()["org_id"] is None

    def test_preset_org_id_from_auth_middleware_is_preserved(self) -> None:
        """Given organization_id is already set by upstream auth,
        When TenantMiddleware processes the request,
        Then it should keep the pre-set value and not overwrite it."""
        client = TestClient(_build_tenant_app(pre_set_org_id="org-from-jwt"))
        resp = client.get("/api/v1/agents")
        assert resp.status_code == 200
        assert resp.json()["org_id"] == "org-from-jwt"

    def test_x_organization_id_header_used_as_fallback(self) -> None:
        """Given no pre-set org_id but X-Organization-ID header is present,
        When TenantMiddleware processes a non-public request,
        Then it should extract org_id from the header."""
        client = TestClient(_build_tenant_app())
        resp = client.get(
            "/api/v1/agents",
            headers={"X-Organization-ID": "org-from-header"},
        )
        assert resp.status_code == 200
        assert resp.json()["org_id"] == "org-from-header"

    def test_missing_org_id_on_non_public_path_is_none(self) -> None:
        """Given no pre-set org_id and no X-Organization-ID header,
        When TenantMiddleware processes a non-public request,
        Then organization_id should be None (no error raised)."""
        client = TestClient(_build_tenant_app())
        resp = client.get("/api/v1/investigations")
        assert resp.status_code == 200
        assert resp.json()["org_id"] is None

    def test_header_ignored_when_org_id_already_set(self) -> None:
        """Given org_id is pre-set by auth AND X-Organization-ID header exists,
        When TenantMiddleware processes the request,
        Then the pre-set value takes precedence over the header."""
        client = TestClient(_build_tenant_app(pre_set_org_id="org-jwt"))
        resp = client.get(
            "/api/v1/agents",
            headers={"X-Organization-ID": "org-header-should-be-ignored"},
        )
        assert resp.status_code == 200
        assert resp.json()["org_id"] == "org-jwt"

    def test_public_path_ignores_header(self) -> None:
        """Given a public path request with an X-Organization-ID header,
        When TenantMiddleware processes it,
        Then organization_id should still be None (public path overrides)."""
        client = TestClient(_build_tenant_app())
        resp = client.get(
            "/health",
            headers={"X-Organization-ID": "org-sneaky"},
        )
        assert resp.status_code == 200
        assert resp.json()["org_id"] is None


# ── TestInMemoryIdempotencyStore ─────────────────────────────────────


class TestInMemoryIdempotencyStore:
    """Feature: In-memory key-value store with TTL-based expiration."""

    @pytest.fixture
    def store(self) -> InMemoryIdempotencyStore:
        return InMemoryIdempotencyStore(ttl=3600)

    @pytest.mark.asyncio
    async def test_get_returns_none_for_missing_key(self, store: InMemoryIdempotencyStore) -> None:
        """Given an empty store,
        When getting a non-existent key,
        Then it should return None."""
        result = await store.get("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_set_and_get_roundtrip(self, store: InMemoryIdempotencyStore) -> None:
        """Given a value is stored,
        When retrieved before TTL expiry,
        Then it should return the stored value."""
        payload = {"body": {"ok": True}, "status_code": 200}
        await store.set("key-1", payload)
        result = await store.get("key-1")
        assert result == payload

    @pytest.mark.asyncio
    async def test_get_returns_none_after_ttl_expiry(self, store: InMemoryIdempotencyStore) -> None:
        """Given a value is stored with a short TTL,
        When retrieved after TTL expires,
        Then it should return None."""
        await store.set("key-exp", {"data": 1}, ttl=1)
        # Simulate time passing beyond TTL
        with patch(
            "shieldops.api.middleware.idempotency.time.monotonic", return_value=time.monotonic() + 2
        ):
            result = await store.get("key-exp")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_removes_entry(self, store: InMemoryIdempotencyStore) -> None:
        """Given a stored entry,
        When deleted,
        Then subsequent get should return None."""
        await store.set("key-del", {"x": 1})
        await store.delete("key-del")
        result = await store.get("key-del")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent_key_is_noop(self, store: InMemoryIdempotencyStore) -> None:
        """Given a key that does not exist,
        When deleting it,
        Then no error is raised."""
        await store.delete("ghost-key")  # Should not raise

    @pytest.mark.asyncio
    async def test_size_reflects_live_entries(self, store: InMemoryIdempotencyStore) -> None:
        """Given multiple stored entries,
        When checking size,
        Then it should count only non-expired entries."""
        await store.set("a", {"v": 1})
        await store.set("b", {"v": 2})
        await store.set("c", {"v": 3}, ttl=1)
        assert store.size >= 2  # 'c' may or may not be expired yet
        # Force expiry of 'c'
        with patch(
            "shieldops.api.middleware.idempotency.time.monotonic", return_value=time.monotonic() + 2
        ):
            assert store.size == 2

    @pytest.mark.asyncio
    async def test_cleanup_removes_expired_entries(self, store: InMemoryIdempotencyStore) -> None:
        """Given entries with expired TTLs,
        When cleanup runs (triggered by get),
        Then expired entries are removed from the internal store."""
        await store.set("fresh", {"v": 1}, ttl=3600)
        await store.set("stale", {"v": 2}, ttl=1)
        with patch(
            "shieldops.api.middleware.idempotency.time.monotonic", return_value=time.monotonic() + 2
        ):
            await store.get("anything")  # triggers _cleanup
            assert "stale" not in store._store
            assert "fresh" in store._store

    @pytest.mark.asyncio
    async def test_custom_ttl_overrides_default(self, store: InMemoryIdempotencyStore) -> None:
        """Given a store with default TTL of 3600,
        When setting a key with ttl=1,
        Then it should expire based on the custom TTL, not the default."""
        await store.set("custom-ttl", {"v": 1}, ttl=1)
        with patch(
            "shieldops.api.middleware.idempotency.time.monotonic", return_value=time.monotonic() + 2
        ):
            result = await store.get("custom-ttl")
        assert result is None

    @pytest.mark.asyncio
    async def test_store_implements_protocol(self) -> None:
        """Given InMemoryIdempotencyStore,
        Then it should satisfy the IdempotencyStore protocol."""
        from shieldops.api.middleware.idempotency import IdempotencyStore

        store = InMemoryIdempotencyStore()
        assert isinstance(store, IdempotencyStore)


# ── TestIdempotencyMiddleware ────────────────────────────────────────


class TestIdempotencyMiddleware:
    """Feature: Prevent duplicate POST/PUT/PATCH via Idempotency-Key header."""

    def test_get_request_bypasses_idempotency(self) -> None:
        """Given a GET request with an Idempotency-Key header,
        When the middleware processes it,
        Then it should pass through without caching."""
        client = TestClient(_build_idempotency_app())
        resp1 = client.get("/api/v1/actions", headers={"Idempotency-Key": "key-1"})
        resp2 = client.get("/api/v1/actions", headers={"Idempotency-Key": "key-1"})
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        # Both requests should actually execute (no caching)
        assert resp2.json()["call_count"] > resp1.json()["call_count"]
        assert "X-Idempotency-Replayed" not in resp2.headers

    def test_delete_request_bypasses_idempotency(self) -> None:
        """Given a DELETE request with an Idempotency-Key header,
        When the middleware processes it,
        Then it should pass through without caching."""
        client = TestClient(_build_idempotency_app())
        resp = client.delete("/api/v1/actions", headers={"Idempotency-Key": "key-1"})
        assert resp.status_code == 200
        assert "X-Idempotency-Replayed" not in resp.headers

    def test_post_without_idempotency_key_passes_through(self) -> None:
        """Given a POST request without Idempotency-Key header,
        When the middleware processes it,
        Then it should pass through without caching."""
        client = TestClient(_build_idempotency_app())
        resp1 = client.post("/api/v1/actions")
        resp2 = client.post("/api/v1/actions")
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        assert resp2.json()["call_count"] > resp1.json()["call_count"]

    def test_post_with_idempotency_key_caches_and_replays(self) -> None:
        """Given a POST request with an Idempotency-Key,
        When the same key is sent again,
        Then the second response should be the cached first response."""
        client = TestClient(_build_idempotency_app())
        resp1 = client.post("/api/v1/actions", headers={"Idempotency-Key": "dedup-1"})
        resp2 = client.post("/api/v1/actions", headers={"Idempotency-Key": "dedup-1"})
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        # Second call should return the cached response, not increment
        assert resp2.json()["call_count"] == resp1.json()["call_count"]

    def test_cached_response_has_replayed_header(self) -> None:
        """Given a cached idempotent response,
        When the duplicate request is served,
        Then the response should include X-Idempotency-Replayed: true."""
        client = TestClient(_build_idempotency_app())
        client.post("/api/v1/actions", headers={"Idempotency-Key": "replay-check"})
        resp2 = client.post("/api/v1/actions", headers={"Idempotency-Key": "replay-check"})
        assert resp2.headers.get("x-idempotency-replayed") == "true"

    def test_first_response_has_no_replayed_header(self) -> None:
        """Given the first request with an Idempotency-Key,
        When the middleware processes it,
        Then the response should NOT have X-Idempotency-Replayed."""
        client = TestClient(_build_idempotency_app())
        resp1 = client.post("/api/v1/actions", headers={"Idempotency-Key": "first-only"})
        assert "x-idempotency-replayed" not in resp1.headers

    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
    def test_idempotency_applies_to_mutating_methods(self, method: str) -> None:
        """Given a mutating HTTP method (POST/PUT/PATCH) with Idempotency-Key,
        When the same key is sent twice,
        Then the second response should be a cached replay."""
        client = TestClient(_build_idempotency_app())
        resp1 = client.request(method, "/api/v1/actions", headers={"Idempotency-Key": "mut-key"})
        resp2 = client.request(method, "/api/v1/actions", headers={"Idempotency-Key": "mut-key"})
        assert resp2.json()["call_count"] == resp1.json()["call_count"]
        assert resp2.headers.get("x-idempotency-replayed") == "true"

    def test_different_methods_same_key_are_independent(self) -> None:
        """Given POST and PUT requests with the same Idempotency-Key,
        When both are sent,
        Then they should be cached independently (different composite keys)."""
        client = TestClient(_build_idempotency_app())
        resp_post = client.post("/api/v1/actions", headers={"Idempotency-Key": "shared-key"})
        resp_put = client.put("/api/v1/actions", headers={"Idempotency-Key": "shared-key"})
        # POST and PUT should each execute independently
        assert resp_put.json()["call_count"] > resp_post.json()["call_count"]

    def test_different_paths_same_key_are_independent(self) -> None:
        """Given POST requests to different paths with the same Idempotency-Key,
        When both are sent,
        Then they should be cached independently."""
        app = Starlette(
            routes=[
                Route("/api/v1/actions", _counting_endpoint, methods=["POST"]),
                Route("/api/v1/other", _counting_endpoint, methods=["POST"]),
            ]
        )
        store = InMemoryIdempotencyStore()
        app.add_middleware(IdempotencyMiddleware, store=store)
        global _call_count
        _call_count = 0
        client = TestClient(app)
        resp1 = client.post("/api/v1/actions", headers={"Idempotency-Key": "path-key"})
        resp2 = client.post("/api/v1/other", headers={"Idempotency-Key": "path-key"})
        assert resp2.json()["call_count"] > resp1.json()["call_count"]

    def test_different_idempotency_keys_are_independent(self) -> None:
        """Given POST requests with different Idempotency-Keys,
        When both are sent to the same path,
        Then each should be processed independently."""
        client = TestClient(_build_idempotency_app())
        resp1 = client.post("/api/v1/actions", headers={"Idempotency-Key": "key-a"})
        resp2 = client.post("/api/v1/actions", headers={"Idempotency-Key": "key-b"})
        assert resp2.json()["call_count"] > resp1.json()["call_count"]

    def test_cached_response_preserves_status_code(self) -> None:
        """Given a cached response with a specific status code,
        When replayed,
        Then the status code should match the original."""
        client = TestClient(_build_idempotency_app())
        resp1 = client.post("/api/v1/actions", headers={"Idempotency-Key": "status-check"})
        resp2 = client.post("/api/v1/actions", headers={"Idempotency-Key": "status-check"})
        assert resp2.status_code == resp1.status_code

    def test_build_key_produces_sha256_composite(self) -> None:
        """Given method, path, and idempotency_key,
        When _build_key is called,
        Then it should return a SHA256 hex digest of the composite."""
        import hashlib

        key = IdempotencyMiddleware._build_key("POST", "/api/v1/actions", "my-key")
        expected = hashlib.sha256(b"POST:/api/v1/actions:my-key").hexdigest()
        assert key == expected
        assert len(key) == 64  # SHA256 hex digest length
