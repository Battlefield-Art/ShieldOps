"""API routes."""

from __future__ import annotations

import time
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger()
router = APIRouter(prefix="/sox-auditor", tags=["sox_auditor"])
_runner: Any = None


def set_runner(runner: Any) -> None:
    global _runner
    _runner = runner


def _get_runner() -> Any:
    if _runner is None:
        raise HTTPException(503, "Service unavailable")
    return _runner


class RunRequest(BaseModel):
    tenant_id: str = ""
    model_config = {"extra": "forbid"}


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok" if _runner else "not_init"}


@router.post("/run")
async def run(
    req: RunRequest,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    runner = _get_runner()
    start = time.time()
    result = await runner.execute(
        tenant_id=req.tenant_id,
    )
    return {
        "request_id": result.request_id,
        "duration_ms": (time.time() - start) * 1000,
        "error": result.error,
    }


@router.get("/runs")
async def list_runs(
    _user: UserResponse = Depends(get_current_user),
) -> list[dict[str, Any]]:
    return _get_runner().list_results()


@router.get("/runs/{run_id}")
async def get_run(
    run_id: str,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    result = _get_runner().get_result(run_id)
    if result is None:
        raise HTTPException(404, "Not found")
    return result.model_dump()
