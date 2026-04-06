"""Deep health-check HTTP endpoint (#8)."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from shieldops.api.health_aggregator import HealthAggregator, HealthStatus

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/health", tags=["Health"])

_aggregator: HealthAggregator | None = None


def set_aggregator(agg: HealthAggregator | None) -> None:
    """Install the health aggregator (injected at startup or in tests)."""
    global _aggregator
    _aggregator = agg


@router.get("/deep")
async def deep_health() -> JSONResponse:
    """Aggregate status of DB, Redis, ClickHouse, OPA, etc."""
    if _aggregator is None:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "detail": "aggregator not initialized"},
        )

    result = await _aggregator.check_all()
    payload: dict[str, Any] = {
        "status": result.status.value,
        "cached": result.cached,
        "checks": {
            name: {
                "ok": c.ok,
                "message": c.message,
                "latency_ms": round(c.latency_ms, 2),
            }
            for name, c in result.checks.items()
        },
    }
    code = 200 if result.status == HealthStatus.HEALTHY else 503
    return JSONResponse(status_code=code, content=payload)
