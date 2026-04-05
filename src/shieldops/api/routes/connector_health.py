"""Connector health check API routes."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse
from shieldops.connectors.health import ConnectorStatus, HealthCheckRegistry

logger = structlog.get_logger()

router = APIRouter(prefix="/connectors", tags=["Connectors"])


class ConnectorHealthResponse(BaseModel):
    """Health status for a single connector."""

    connector_name: str
    status: ConnectorStatus
    latency_ms: float
    last_checked: str
    message: str = ""


class ConnectorHealthListResponse(BaseModel):
    """Response for the connector health endpoint."""

    connectors: list[ConnectorHealthResponse]
    total: int
    healthy: int
    degraded: int
    unavailable: int


@router.get("/health")
async def get_connector_health(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Return health status for all registered connectors.

    Runs health checks (with caching) for every connector in the registry
    and returns a summary with per-connector status.
    """
    registry = HealthCheckRegistry()
    statuses = await registry.check_all()

    connectors: list[dict[str, Any]] = []
    healthy_count = 0
    degraded_count = 0
    unavailable_count = 0

    for name, status in sorted(statuses.items()):
        connectors.append(
            {
                "connector_name": name,
                "status": status.status.value,
                "latency_ms": round(status.latency_ms, 2),
                "last_checked": status.last_checked.isoformat(),
                "message": status.message,
            }
        )
        if status.status == ConnectorStatus.HEALTHY:
            healthy_count += 1
        elif status.status == ConnectorStatus.DEGRADED:
            degraded_count += 1
        else:
            unavailable_count += 1

    return {
        "connectors": connectors,
        "total": len(connectors),
        "healthy": healthy_count,
        "degraded": degraded_count,
        "unavailable": unavailable_count,
    }
