"""Asset inventory API routes."""

from __future__ import annotations

import time
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger()
router = APIRouter(prefix="/asset-inventory", tags=["Asset Inventory"])
_runner: Any = None


def set_runner(runner: Any) -> None:
    global _runner
    _runner = runner


def get_runner() -> Any:
    return _runner


def _get_runner() -> Any:
    if _runner is None:
        raise HTTPException(503, "asset_inventory service unavailable")
    return _runner


class RunRequest(BaseModel):
    tenant_id: str = ""
    scan_scope: str = "all"
    model_config = {"extra": "forbid"}


@router.get("/health")
async def health() -> dict[str, Any]:
    return {
        "service": "asset_inventory",
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
        result = await runner.manage(
            tenant_id=body.tenant_id,
        )
        return {"status": "completed", "result": result}
    except Exception as e:
        logger.exception("asset_inventory.run.error")
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


@router.get("/assets")
async def list_assets(
    limit: int = 50,
    asset_type: str = "",
    criticality: str = "",
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    return {"assets": [], "total": 0}


@router.get("/assets/{asset_id}")
async def get_asset(
    asset_id: str,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    return {"asset_id": asset_id, "status": "not_found"}
