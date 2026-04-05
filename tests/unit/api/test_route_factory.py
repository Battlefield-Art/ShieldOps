"""Tests for the route factory — create_agent_router."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import APIRouter, FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel

from shieldops.api.routes.factory import create_agent_router

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_app(name: str, **kwargs: Any) -> tuple[FastAPI, Any, Any]:
    """Build a minimal FastAPI app with a factory-generated router."""
    router, set_runner = create_agent_router(name, **kwargs)
    app = FastAPI()
    app.include_router(router)

    # Override auth dependency globally so tests don't need a real JWT.
    from shieldops.api.auth.dependencies import get_current_user
    from shieldops.api.auth.models import UserResponse, UserRole

    fake_user = UserResponse(
        id="u-1", email="test@test.com", name="Test", role=UserRole.ADMIN, is_active=True
    )
    app.dependency_overrides[get_current_user] = lambda: fake_user

    return app, router, set_runner


def _client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_health_not_initialized() -> None:
    app, _, _ = _make_app("demo_agent")
    async with _client(app) as c:
        resp = await c.get("/demo-agent/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "demo-agent"
    assert data["status"] == "not_initialized"
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_health_initialized() -> None:
    app, _, set_runner = _make_app("demo_agent")
    set_runner(MagicMock())
    async with _client(app) as c:
        resp = await c.get("/demo-agent/health")
    assert resp.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_run_calls_runner() -> None:
    app, _, set_runner = _make_app("demo_agent")
    runner = MagicMock()
    runner.execute = AsyncMock(return_value={"score": 42})
    set_runner(runner)
    async with _client(app) as c:
        resp = await c.post("/demo-agent/run", json={"tenant_id": "t-1"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "completed"
    assert body["result"] == {"score": 42}
    runner.execute.assert_awaited_once_with(tenant_id="t-1")


@pytest.mark.asyncio
async def test_run_returns_503_when_not_initialized() -> None:
    app, _, _ = _make_app("demo_agent")
    async with _client(app) as c:
        resp = await c.post("/demo-agent/run", json={})
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_run_pydantic_result() -> None:
    """When the runner returns a Pydantic model, .model_dump() is used."""

    class FakeResult(BaseModel):
        value: int = 7

    app, _, set_runner = _make_app("demo_agent")
    runner = MagicMock()
    runner.execute = AsyncMock(return_value=FakeResult())
    set_runner(runner)
    async with _client(app) as c:
        resp = await c.post("/demo-agent/run", json={})
    assert resp.json()["result"] == {"value": 7}


@pytest.mark.asyncio
async def test_list_runs() -> None:
    app, _, set_runner = _make_app("demo_agent")
    runner = MagicMock()
    runner.list_runs = MagicMock(return_value=[{"id": "r1"}])
    set_runner(runner)
    async with _client(app) as c:
        resp = await c.get("/demo-agent/runs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["runs"] == [{"id": "r1"}]
    assert data["total"] == 1


@pytest.mark.asyncio
async def test_list_runs_503() -> None:
    app, _, _ = _make_app("demo_agent")
    async with _client(app) as c:
        resp = await c.get("/demo-agent/runs")
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_get_run_not_found() -> None:
    app, _, set_runner = _make_app("demo_agent")
    runner = MagicMock(spec=[])  # no get_result / get_run attrs
    set_runner(runner)
    async with _client(app) as c:
        resp = await c.get("/demo-agent/runs/missing-123")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_run_found() -> None:
    app, _, set_runner = _make_app("demo_agent")
    runner = MagicMock()
    runner.get_result = MagicMock(return_value={"id": "r1", "status": "done"})
    set_runner(runner)
    async with _client(app) as c:
        resp = await c.get("/demo-agent/runs/r1")
    assert resp.status_code == 200
    assert resp.json()["id"] == "r1"


@pytest.mark.asyncio
async def test_custom_request_model() -> None:
    class ScanRequest(BaseModel):
        target: str
        depth: int = 3
        model_config = {"extra": "forbid"}

    app, _, set_runner = _make_app("scanner", run_method="scan", request_model=ScanRequest)
    runner = MagicMock()
    runner.scan = AsyncMock(return_value={"findings": 0})
    set_runner(runner)
    async with _client(app) as c:
        resp = await c.post("/scanner/run", json={"target": "10.0.0.1"})
    assert resp.status_code == 200
    runner.scan.assert_awaited_once_with(target="10.0.0.1")


@pytest.mark.asyncio
async def test_extra_routes() -> None:
    def add_extras(r: APIRouter, get_runner: Any) -> None:
        @r.get("/custom-endpoint", operation_id="demo_custom")
        async def custom() -> dict[str, str]:
            return {"extra": "ok"}

    app, _, _ = _make_app("demo_agent", extra_routes=add_extras)
    async with _client(app) as c:
        resp = await c.get("/demo-agent/custom-endpoint")
    assert resp.status_code == 200
    assert resp.json() == {"extra": "ok"}


@pytest.mark.asyncio
async def test_different_run_methods() -> None:
    """run_method='investigate' routes to runner.investigate()."""
    app, _, set_runner = _make_app("xdr_lite", run_method="investigate")
    runner = MagicMock()
    runner.investigate = AsyncMock(return_value={"alert": True})
    set_runner(runner)
    async with _client(app) as c:
        resp = await c.post("/xdr-lite/run", json={})
    assert resp.status_code == 200
    runner.investigate.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_method_missing_returns_500() -> None:
    app, _, set_runner = _make_app("broken", run_method="nonexistent")
    runner = MagicMock(spec=[])  # no methods
    set_runner(runner)
    async with _client(app) as c:
        resp = await c.post("/broken/run", json={})
    assert resp.status_code == 500


@pytest.mark.asyncio
async def test_operation_ids_unique() -> None:
    """Each factory-generated router should have unique operation_ids."""
    _, router_a, _ = _make_app("agent_a")
    _, router_b, _ = _make_app("agent_b")
    ids_a = {r.operation_id for r in router_a.routes if hasattr(r, "operation_id")}
    ids_b = {r.operation_id for r in router_b.routes if hasattr(r, "operation_id")}
    assert ids_a.isdisjoint(ids_b), f"Colliding operation_ids: {ids_a & ids_b}"
