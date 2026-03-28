"""Threat Feed Manager API routes."""

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
    prefix="/threat-feed-manager",
    tags=["Threat Feed Manager"],
)
_runner: Any = None


def set_runner(runner: Any) -> None:
    global _runner
    _runner = runner


def _get_runner() -> Any:
    if _runner is None:
        raise HTTPException(503, "threat_feed_manager service unavailable")
    return _runner


class RunRequest(BaseModel):
    tenant_id: str = ""
    model_config = {"extra": "forbid"}


@router.get("/health")
async def health() -> dict[str, Any]:
    return {
        "service": "threat_feed_manager",
        "status": "healthy" if _runner else "not_initialized",
        "timestamp": time.time(),
    }


@router.post("/run")
async def run_agent(
    body: RunRequest,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    runner = _get_runner()
    try:
        result = await runner.execute(tenant_id=body.tenant_id)
        return {"status": "completed", "result": result.model_dump()}
    except Exception as e:
        logger.exception("threat_feed_manager.run.error")
        raise HTTPException(500, str(e)) from e


@router.get("/runs")
async def list_runs(
    limit: int = 20,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    if _runner is None:
        return {"runs": [], "total": 0}
    runs = _runner.list_results()
    return {"runs": runs[:limit], "total": len(runs)}


@router.get("/runs/{run_id}")
async def get_run(
    run_id: str,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    if _runner is None:
        return {"run_id": run_id, "status": "not_found"}
    result = _runner.get_result(run_id)
    if result is None:
        return {"run_id": run_id, "status": "not_found"}
    return {"run_id": run_id, "status": "found", "result": result.model_dump()}
