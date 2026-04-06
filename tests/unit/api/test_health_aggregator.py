"""Deep health check aggregator — TDD tests (#8)."""

from __future__ import annotations

import asyncio
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from shieldops.api.health_aggregator import (
    HealthAggregator,
    HealthCheck,
    HealthStatus,
)


def _ok_check(name: str) -> HealthCheck:
    async def _probe() -> tuple[bool, str]:
        return (True, "ok")

    return HealthCheck(name=name, probe=_probe)


def _fail_check(name: str, reason: str = "down") -> HealthCheck:
    async def _probe() -> tuple[bool, str]:
        return (False, reason)

    return HealthCheck(name=name, probe=_probe)


def _slow_check(name: str, delay: float) -> HealthCheck:
    async def _probe() -> tuple[bool, str]:
        await asyncio.sleep(delay)
        return (True, "ok after sleep")

    return HealthCheck(name=name, probe=_probe)


class TestHealthAggregatorAllHealthy:
    @pytest.mark.asyncio
    async def test_all_ok_returns_healthy(self) -> None:
        agg = HealthAggregator([_ok_check("db"), _ok_check("redis")], cache_ttl_s=0)
        result = await agg.check_all()
        assert result.status == HealthStatus.HEALTHY
        assert result.checks["db"].ok is True
        assert result.checks["redis"].ok is True


class TestHealthAggregatorDegraded:
    @pytest.mark.asyncio
    async def test_one_failing_returns_unhealthy(self) -> None:
        agg = HealthAggregator(
            [_ok_check("db"), _fail_check("redis", "connection refused")],
            cache_ttl_s=0,
        )
        result = await agg.check_all()
        assert result.status == HealthStatus.UNHEALTHY
        assert result.checks["redis"].ok is False
        assert "connection refused" in result.checks["redis"].message


class TestHealthAggregatorTimeout:
    @pytest.mark.asyncio
    async def test_slow_check_times_out(self) -> None:
        """A probe that exceeds the per-check timeout is marked unhealthy."""
        agg = HealthAggregator(
            [_slow_check("slow-dep", delay=2.0)],
            cache_ttl_s=0,
            per_check_timeout_s=0.1,
        )
        start = time.monotonic()
        result = await agg.check_all()
        elapsed = time.monotonic() - start
        assert elapsed < 0.5  # timeout honored, not waited 2s
        assert result.status == HealthStatus.UNHEALTHY
        assert result.checks["slow-dep"].ok is False
        assert "timeout" in result.checks["slow-dep"].message.lower()


class TestHealthAggregatorCaching:
    @pytest.mark.asyncio
    async def test_cached_results_within_ttl(self) -> None:
        call_count = 0

        async def _probe() -> tuple[bool, str]:
            nonlocal call_count
            call_count += 1
            return (True, "ok")

        agg = HealthAggregator(
            [HealthCheck(name="db", probe=_probe)],
            cache_ttl_s=10,
        )
        await agg.check_all()
        await agg.check_all()
        await agg.check_all()
        assert call_count == 1  # Only probed once


class TestHealthAggregatorHTTPRoute:
    def test_deep_health_endpoint_200_when_healthy(self) -> None:
        from shieldops.api.routes import health_deep

        health_deep.set_aggregator(HealthAggregator([_ok_check("db")], cache_ttl_s=0))
        app = FastAPI()
        app.include_router(health_deep.router)
        client = TestClient(app)
        r = client.get("/health/deep")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert "db" in data["checks"]

    def test_deep_health_endpoint_503_when_unhealthy(self) -> None:
        from shieldops.api.routes import health_deep

        health_deep.set_aggregator(HealthAggregator([_fail_check("redis")], cache_ttl_s=0))
        app = FastAPI()
        app.include_router(health_deep.router)
        client = TestClient(app)
        r = client.get("/health/deep")
        assert r.status_code == 503
        data = r.json()
        assert data["status"] == "unhealthy"
