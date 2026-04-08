"""Agent fitness & promotion API routes.

Endpoints:
- ``GET  /api/v1/agents/fitness``                     — fitness + status for all agents
- ``GET  /api/v1/agents/{name}/fitness/history``      — historical fitness trend
- ``POST /api/v1/agents/{name}/promote``              — manual promote (admin)
- ``POST /api/v1/agents/{name}/demote``               — manual demote (admin)
- ``GET  /api/v1/agents/leaderboard``                 — fitness leaderboard

Backed by :class:`shieldops.utils.evolution.store.EvolutionStore` via
``Depends(get_evolution_store)`` (RFC #246 PR-5). The legacy
``fitness_aggregator``/``promotion_engine`` modules are no longer
imported here; deletion lands in PR-6 (#279).
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse, UserRole
from shieldops.utils.evolution.composition import get_evolution_store
from shieldops.utils.evolution.store import EvolutionStore

logger = structlog.get_logger()

router = APIRouter(prefix="/agents", tags=["Agent Promotion"])


# ── Response models ───────────────────────────────────────────────────


class AgentFitnessRow(BaseModel):
    agent_name: str
    org_id: str
    status: str
    composite_fitness: float
    promoted_at: str | None = None
    demoted_at: str | None = None
    rank: int | None = None


class FitnessListResponse(BaseModel):
    items: list[AgentFitnessRow]
    total: int


class FitnessHistoryPoint(BaseModel):
    day_epoch: float
    composite: float
    dimensions: dict[str, float] = Field(default_factory=dict)
    sample_count: int = 0


class FitnessHistoryResponse(BaseModel):
    agent_name: str
    window_days: int
    composite_current: float
    composite_avg: float
    min_composite: float
    max_composite: float
    sample_count: int
    points: list[FitnessHistoryPoint]


class StatusChangeRequest(BaseModel):
    reason: str = ""
    org_id: str = "default"
    disable: bool = False  # only honored by demote
    model_config = {"extra": "forbid"}


class StatusChangeResponse(BaseModel):
    agent_name: str
    org_id: str
    status: str
    composite_fitness: float
    action: str
    reason: str


# ── Helpers ───────────────────────────────────────────────────────────


def _require_admin(user: UserResponse) -> None:
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="admin role required")


# ── Endpoints ─────────────────────────────────────────────────────────


@router.get("/fitness", response_model=FitnessListResponse)
async def list_agent_fitness(
    org_id: str | None = Query(None, description="Filter to a single org"),
    user: UserResponse = Depends(get_current_user),
    store: EvolutionStore = Depends(get_evolution_store),
) -> FitnessListResponse:
    """Return fitness scores + status for every tracked agent."""
    rows = store.leaderboard_rows(org_id=org_id, top_n=10_000)
    items = [AgentFitnessRow(**row) for row in rows]
    return FitnessListResponse(items=items, total=len(items))


@router.get("/leaderboard", response_model=FitnessListResponse)
async def fitness_leaderboard(
    org_id: str | None = Query(None),
    top_n: int = Query(50, ge=1, le=500),
    user: UserResponse = Depends(get_current_user),
    store: EvolutionStore = Depends(get_evolution_store),
) -> FitnessListResponse:
    """Return agents sorted by composite fitness (descending)."""
    rows = store.leaderboard_rows(org_id=org_id, top_n=top_n)
    items = [AgentFitnessRow(**row) for row in rows]
    return FitnessListResponse(items=items, total=len(items))


@router.get("/{agent_name}/fitness/history", response_model=FitnessHistoryResponse)
async def agent_fitness_history(
    agent_name: str,
    window_days: int = Query(7, ge=1, le=90),
    user: UserResponse = Depends(get_current_user),
    store: EvolutionStore = Depends(get_evolution_store),
) -> FitnessHistoryResponse:
    """Historical composite fitness trend for a single agent."""
    window = store.rolling_window(agent_name, window_days=window_days)
    return FitnessHistoryResponse(
        agent_name=window.agent_name,
        window_days=window.window_days,
        composite_current=window.composite_current,
        composite_avg=window.composite_avg,
        min_composite=window.min_composite,
        max_composite=window.max_composite,
        sample_count=window.sample_count,
        points=[
            FitnessHistoryPoint(
                day_epoch=p.day_epoch,
                composite=p.composite,
                dimensions=p.dimensions,
                sample_count=p.sample_count,
            )
            for p in window.daily_points
        ],
    )


@router.post("/{agent_name}/promote", response_model=StatusChangeResponse)
async def promote_agent(
    agent_name: str,
    body: StatusChangeRequest,
    user: UserResponse = Depends(get_current_user),
    store: EvolutionStore = Depends(get_evolution_store),
) -> StatusChangeResponse:
    """Manually promote an agent to GA (admin only)."""
    _require_admin(user)
    try:
        snap = store.promote_agent(
            agent_name,
            org_id=body.org_id,
            reason=body.reason or f"manual promotion by {user.email}",
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return StatusChangeResponse(
        agent_name=snap.agent_name,
        org_id=snap.org_id,
        status=snap.status.value,
        composite_fitness=snap.current_fitness,
        action="promoted",
        reason=body.reason,
    )


@router.post("/{agent_name}/demote", response_model=StatusChangeResponse)
async def demote_agent(
    agent_name: str,
    body: StatusChangeRequest,
    user: UserResponse = Depends(get_current_user),
    store: EvolutionStore = Depends(get_evolution_store),
) -> StatusChangeResponse:
    """Manually demote an agent from GA (admin only)."""
    _require_admin(user)
    try:
        snap = store.demote_agent(
            agent_name,
            org_id=body.org_id,
            reason=body.reason or f"manual demotion by {user.email}",
            disable=body.disable,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return StatusChangeResponse(
        agent_name=snap.agent_name,
        org_id=snap.org_id,
        status=snap.status.value,
        composite_fitness=snap.current_fitness,
        action="demoted",
        reason=body.reason,
    )


__all__: list[str] = ["router"]


def set_engine(_: Any) -> None:  # pragma: no cover - compatibility shim
    """No-op setter kept for route-factory compatibility."""
    return None
