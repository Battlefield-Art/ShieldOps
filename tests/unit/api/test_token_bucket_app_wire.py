"""TokenBucketMiddleware wired into a FastAPI app (TDD #3-wire).

Verifies install_token_bucket_middleware():
- adds the middleware
- exempt paths bypass the bucket
- 429 is returned past capacity
- key function pulls api key from Authorization header / X-API-Key
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.middleware.token_bucket_wiring import (
    install_token_bucket_middleware,
)


def _build_app(capacity: int = 3, rate: float = 1.0) -> FastAPI:
    app = FastAPI()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/v1/thing")
    def thing() -> dict[str, str]:
        return {"thing": "value"}

    install_token_bucket_middleware(
        app,
        capacity=capacity,
        refill_rate_per_sec=rate,
        exempt_paths=["/health", "/metrics"],
    )
    return app


class TestTokenBucketAppWire:
    def test_capacity_enforced(self) -> None:
        app = _build_app(capacity=2)
        client = TestClient(app)
        headers = {"X-API-Key": "abc"}
        assert client.get("/api/v1/thing", headers=headers).status_code == 200
        assert client.get("/api/v1/thing", headers=headers).status_code == 200
        r = client.get("/api/v1/thing", headers=headers)
        assert r.status_code == 429
        assert "Retry-After" in r.headers

    def test_exempt_paths_bypass_limiter(self) -> None:
        app = _build_app(capacity=1)
        client = TestClient(app)
        headers = {"X-API-Key": "abc"}
        # Burn the bucket
        assert client.get("/api/v1/thing", headers=headers).status_code == 200
        assert client.get("/api/v1/thing", headers=headers).status_code == 429
        # Health endpoint is exempt
        for _ in range(10):
            assert client.get("/health").status_code == 200

    def test_independent_api_keys(self) -> None:
        app = _build_app(capacity=2)
        client = TestClient(app)
        # Exhaust key alpha
        assert client.get("/api/v1/thing", headers={"X-API-Key": "alpha"}).status_code == 200
        assert client.get("/api/v1/thing", headers={"X-API-Key": "alpha"}).status_code == 200
        assert client.get("/api/v1/thing", headers={"X-API-Key": "alpha"}).status_code == 429
        # Key beta unaffected
        assert client.get("/api/v1/thing", headers={"X-API-Key": "beta"}).status_code == 200

    def test_authorization_header_fallback(self) -> None:
        """If X-API-Key not present, use Authorization Bearer token as key."""
        app = _build_app(capacity=1)
        client = TestClient(app)
        auth = {"Authorization": "Bearer token-xyz"}
        assert client.get("/api/v1/thing", headers=auth).status_code == 200
        assert client.get("/api/v1/thing", headers=auth).status_code == 429

    def test_ip_fallback_when_no_auth(self) -> None:
        app = _build_app(capacity=1)
        client = TestClient(app)
        assert client.get("/api/v1/thing").status_code == 200
        assert client.get("/api/v1/thing").status_code == 429
