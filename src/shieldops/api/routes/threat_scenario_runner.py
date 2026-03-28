"""Threat Scenario Runner API routes."""

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
    prefix="/threat-scenarios",
    tags=["Threat Scenario Runner"],
)
_runner: Any = None


def set_runner(runner: Any) -> None:
    global _runner
    _runner = runner


def _get_runner() -> Any:
    if _runner is None:
        raise HTTPException(
            503,
            "threat_scenario_runner service unavailable",
        )
    return _runner


class RunRequest(BaseModel):
    tenant_id: str = ""
    scenario_name: str = ""
    model_config = {"extra": "forbid"}


@router.get("/health")
async def health() -> dict[str, Any]:
    return {
        "service": "threat_scenario_runner",
        "status": ("healthy" if _runner else "not_initialized"),
        "timestamp": time.time(),
    }


@router.post("/run")
async def run_agent(
    body: RunRequest,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    runner = _get_runner()
    try:
        result = await runner.run_scenario(
            tenant_id=body.tenant_id,
            scenario_name=body.scenario_name,
        )
        return {"status": "completed", "result": result}
    except Exception as e:
        logger.exception("threat_scenario_runner.run.error")
        raise HTTPException(500, str(e)) from e


@router.get("/runs")
async def list_runs(
    limit: int = 20,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    return {"runs": [], "total": 0}


@router.get("/runs/{run_id}")
async def get_run(
    run_id: str,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    return {"run_id": run_id, "status": "not_found"}
