"""Compliance auditor API routes — LangGraph agent-based."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from shieldops.agents.compliance_auditor.models import ComplianceFramework
from shieldops.api.auth.dependencies import require_role

logger = structlog.get_logger()
router = APIRouter(
    prefix="/compliance-auditor",
    tags=["Compliance Auditor"],
)

_runner: Any = None


def set_runner(runner: Any) -> None:
    global _runner
    _runner = runner


def _get_runner() -> Any:
    if _runner is None:
        raise HTTPException(503, "Compliance auditor service unavailable")
    return _runner


class RunAuditRequest(BaseModel):
    frameworks: list[str] = Field(
        default=["soc2"],
        description="Compliance frameworks to audit (soc2, pci_dss, hipaa, gdpr, iso27001)",
    )


@router.post("/run")
async def run_audit(
    body: RunAuditRequest,
    _user: Any = Depends(require_role("operator")),  # type: ignore[arg-type]
) -> dict[str, Any]:
    """Run a compliance audit for the specified frameworks."""
    runner = _get_runner()
    try:
        result = await runner.run(frameworks=body.frameworks)
        if hasattr(result, "model_dump"):
            return result.model_dump()  # type: ignore[no-any-return]
        return dict(result)
    except Exception as e:
        logger.error("compliance_audit_failed", error=str(e))
        raise HTTPException(500, f"Audit failed: {e}") from e


@router.get("/frameworks")
async def list_frameworks(
    _user: Any = Depends(require_role("viewer")),  # type: ignore[arg-type]
) -> list[str]:
    """List available compliance frameworks."""
    return [f.value for f in ComplianceFramework]
