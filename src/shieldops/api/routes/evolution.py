"""Evolution Engine API routes."""

from __future__ import annotations

import time
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger()
router = APIRouter(
    prefix="/evolution",
    tags=["Agent Evolution"],
)
_runner: Any = None


def set_runner(runner: Any) -> None:
    global _runner
    _runner = runner


def get_runner() -> Any:
    return _runner


def _get_runner() -> Any:
    if _runner is None:
        raise HTTPException(503, "Evolution Engine unavailable")
    return _runner


class EvolveRequest(BaseModel):
    target_agent_ids: list[str] = []
    max_candidates: int = 10
    dry_run: bool = False
    tenant_id: str = ""

    model_config = {"extra": "forbid"}


class FitnessQueryRequest(BaseModel):
    agent_id: str = ""
    dimension: str = ""
    top_n: int = 20


class PromptMutateRequest(BaseModel):
    agent_id: str
    node_name: str
    new_content: str
    mutation_type: str = "llm_rewrite"
    reason: str = ""


# --- Health ---


@router.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok" if _runner else "unavailable",
        "timestamp": time.time(),
        "service": "evolution_engine",
    }


# --- Evolution Cycles ---


@router.post("/evolve")
async def run_evolution(
    req: EvolveRequest,
    user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    runner = _get_runner()
    result = await runner.evolve(
        target_agent_ids=req.target_agent_ids or None,
        max_candidates=req.max_candidates,
        dry_run=req.dry_run,
        tenant_id=req.tenant_id,
    )
    return {
        "request_id": result.request_id,
        "candidates": result.total_candidates,
        "mutations": result.total_mutations,
        "deployments": result.total_deployments,
        "learnings_propagated": result.total_learnings_propagated,
        "fleet_fitness_before": result.fleet_fitness_before,
        "fleet_fitness_after": result.fleet_fitness_after,
        "improvement_pct": result.improvement_pct,
        "reasoning_chain": result.reasoning_chain,
    }


@router.get("/runs")
async def list_runs(
    user: UserResponse = Depends(get_current_user),
) -> list[dict[str, Any]]:
    runner = _get_runner()
    return runner.list_results()


@router.get("/runs/{request_id}")
async def get_run(
    request_id: str,
    user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    runner = _get_runner()
    result = runner.get_result(request_id)
    if not result:
        raise HTTPException(404, f"Evolution run {request_id} not found")
    return result.model_dump()


# --- Fitness ---


@router.get("/fitness/leaderboard")
async def fitness_leaderboard(
    top_n: int = 20,
    dimension: str = "",
    user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    from shieldops.utils.fitness_tracker import FitnessDimension, get_fitness_tracker

    tracker = get_fitness_tracker()
    dim = FitnessDimension(dimension) if dimension else None
    leaderboard = tracker.get_leaderboard(top_n=top_n, dimension=dim)
    return {
        "leaderboard": [e.model_dump() for e in leaderboard],
        "stats": tracker.get_stats(),
    }


@router.get("/fitness/{agent_id}")
async def get_agent_fitness(
    agent_id: str,
    user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    from shieldops.utils.fitness_tracker import get_fitness_tracker

    tracker = get_fitness_tracker()
    fitness = tracker.get_fitness(agent_id)
    return fitness.model_dump()


# --- Prompt Evolution ---


@router.get("/prompts/{agent_id}/{node_name}/lineage")
async def get_prompt_lineage(
    agent_id: str,
    node_name: str,
    user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    from shieldops.utils.prompt_evolution import get_prompt_store

    store = get_prompt_store()
    lineage = store.get_lineage(agent_id, node_name)
    return lineage.model_dump()


@router.post("/prompts/mutate")
async def mutate_prompt(
    req: PromptMutateRequest,
    user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    from shieldops.utils.prompt_evolution import MutationType, get_prompt_store

    store = get_prompt_store()
    version = store.mutate(
        agent_id=req.agent_id,
        node_name=req.node_name,
        new_content=req.new_content,
        mutation_type=MutationType(req.mutation_type),
        reason=req.reason,
    )
    return version.model_dump()


@router.post("/prompts/{agent_id}/{node_name}/rollback")
async def rollback_prompt(
    agent_id: str,
    node_name: str,
    user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    from shieldops.utils.prompt_evolution import get_prompt_store

    store = get_prompt_store()
    result = store.rollback(agent_id, node_name)
    if not result:
        raise HTTPException(404, "No prompt to rollback to")
    return result.model_dump()


@router.get("/prompts/stats")
async def prompt_stats(
    user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    from shieldops.utils.prompt_evolution import get_prompt_store

    return get_prompt_store().get_stats()


# --- Learning Bus ---


@router.get("/learnings")
async def list_learnings(
    event_type: str = "",
    min_confidence: float = 0.0,
    limit: int = 50,
    user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    from shieldops.utils.learning_bus import LearningEventType, get_learning_bus

    bus = get_learning_bus()
    et = LearningEventType(event_type) if event_type else None
    events = bus.get_events(
        event_type=et,
        min_confidence=min_confidence,
        limit=limit,
    )
    return {
        "events": [e.model_dump() for e in events],
        "stats": bus.get_stats(),
    }


@router.get("/learnings/shared-patterns")
async def shared_patterns(
    min_applications: int = 3,
    user: UserResponse = Depends(get_current_user),
) -> list[dict[str, Any]]:
    from shieldops.utils.learning_bus import get_learning_bus

    bus = get_learning_bus()
    patterns = bus.get_shared_patterns(min_applications=min_applications)
    return [p.model_dump() for p in patterns]
