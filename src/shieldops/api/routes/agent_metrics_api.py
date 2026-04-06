"""Agent Metrics dashboard API — per-agent, fleet, and time-series endpoints.

Aggregates `AgentRun` records into dashboard-friendly shapes:
- Per-agent success rate, duration, tokens, estimated cost
- Fleet-wide totals
- Time-series trends (buckets per hour or day)

The underlying aggregations live in ``AgentRunRepository``; this module
exposes thin FastAPI handlers that enforce org isolation and shape the
response payloads.
"""

from __future__ import annotations

from typing import Any, Literal

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse
from shieldops.db.repositories.agent_run import AgentRunRepository

logger = structlog.get_logger()

router = APIRouter(prefix="/agents/metrics", tags=["Agent Metrics"])

_run_repo: AgentRunRepository | None = None

# Ranges allowed per endpoint.
MetricsRange = Literal["1h", "6h", "24h", "7d", "30d"]
TrendRange = Literal["24h", "7d", "30d"]


def set_run_repository(repo: AgentRunRepository) -> None:
    """Inject the AgentRunRepository (called during app startup)."""
    global _run_repo
    _run_repo = repo


def _get_run_repo() -> AgentRunRepository:
    if _run_repo is None:
        raise HTTPException(status_code=503, detail="Agent run repository not initialized")
    return _run_repo


def _extract_org_id(user: UserResponse) -> str:
    """Extract org_id from the authenticated user (mirrors agent_runs.py)."""
    return getattr(user, "org_id", None) or user.id


# ── Response models ───────────────────────────────────────────────────


class AgentMetric(BaseModel):
    """Aggregated metrics for a single agent over the requested range."""

    agent_name: str
    total_runs: int
    success_count: int
    failure_count: int
    success_rate: float = Field(ge=0.0, le=1.0)
    avg_duration_ms: float
    max_duration_ms: int
    total_tokens: int
    estimated_cost_usd: float


class AgentMetricsResponse(BaseModel):
    range: str
    agents: list[AgentMetric]


class FleetMetricsResponse(BaseModel):
    range: str
    total_agents: int
    total_runs: int
    total_success: int
    total_failure: int
    fleet_success_rate: float = Field(ge=0.0, le=1.0)
    avg_duration_ms: float
    total_tokens: int
    estimated_cost_usd: float


class TrendPoint(BaseModel):
    bucket: str | None
    agent_name: str
    runs: int
    success_rate: float
    avg_duration_ms: float
    total_tokens: int


class TrendsResponse(BaseModel):
    range: str
    granularity: Literal["hour", "day"]
    points: list[TrendPoint]


# ── Endpoints ─────────────────────────────────────────────────────────


@router.get("", response_model=AgentMetricsResponse)
async def list_agent_metrics(
    range: MetricsRange = Query("24h", description="Time window for aggregation"),
    user: UserResponse = Depends(get_current_user),
) -> AgentMetricsResponse:
    """Return per-agent aggregated metrics for the caller's org."""
    repo = _get_run_repo()
    org_id = _extract_org_id(user)
    rows = await repo.aggregate_by_agent(org_id=org_id, range_str=range)
    return AgentMetricsResponse(
        range=range,
        agents=[AgentMetric(**row) for row in rows],
    )


@router.get("/fleet", response_model=FleetMetricsResponse)
async def get_fleet_metrics(
    range: MetricsRange = Query("24h", description="Time window for aggregation"),
    user: UserResponse = Depends(get_current_user),
) -> FleetMetricsResponse:
    """Return fleet-wide totals across all agents for the caller's org."""
    repo = _get_run_repo()
    org_id = _extract_org_id(user)
    summary: dict[str, Any] = await repo.aggregate_fleet(org_id=org_id, range_str=range)
    return FleetMetricsResponse(**summary)


@router.get("/trends", response_model=TrendsResponse)
async def get_metrics_trends(
    range: TrendRange = Query("7d", description="Time window for the trend chart"),
    agent_name: str | None = Query(None, description="Optional agent filter"),
    user: UserResponse = Depends(get_current_user),
) -> TrendsResponse:
    """Return a bucketed time-series for trend charts (hour for 24h, day otherwise)."""
    repo = _get_run_repo()
    org_id = _extract_org_id(user)
    points = await repo.time_series_by_agent(
        org_id=org_id,
        range_str=range,
        agent_name=agent_name,
    )
    granularity: Literal["hour", "day"] = "hour" if range == "24h" else "day"
    return TrendsResponse(
        range=range,
        granularity=granularity,
        points=[TrendPoint(**p) for p in points],
    )
