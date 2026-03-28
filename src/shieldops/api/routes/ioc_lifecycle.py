"""IOC Lifecycle Agent API routes."""

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
    prefix="/ioc-lifecycle",
    tags=["IOC Lifecycle"],
)
_runner: Any = None


def set_runner(runner: Any) -> None:
    global _runner
    _runner = runner


def _get_runner() -> Any:
    if _runner is None:
        raise HTTPException(
            503,
            "ioc_lifecycle service unavailable",
        )
    return _runner


class RunRequest(BaseModel):
    tenant_id: str = ""
    sources: list[str] = []
    model_config = {"extra": "forbid"}


@router.get("/health")
async def health() -> dict[str, Any]:
    return {
        "service": "ioc_lifecycle",
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
        result = await runner.execute(
            tenant_id=body.tenant_id,
            sources=body.sources or None,
        )
        return {"status": "completed", "result": result.model_dump()}
    except Exception as e:
        logger.exception("ioc_lifecycle.run.error")
        raise HTTPException(500, str(e)) from e


@router.get("/runs")
async def list_runs(
    limit: int = 20,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    if _runner is None:
        return {"runs": [], "total": 0}
    return {
        "runs": _runner.list_results()[:limit],
        "total": len(_runner.list_results()),
    }


@router.get("/runs/{run_id}")
async def get_run(
    run_id: str,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    if _runner is None:
        return {"run_id": run_id, "status": "not_found"}
    result = _runner.get_result(run_id)
    if result is None:
        raise HTTPException(404, f"Run '{run_id}' not found")
    return result.model_dump()
