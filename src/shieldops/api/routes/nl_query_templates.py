"""NL Query SOC template API endpoints (#3, #235).

Lists and runs SOC workflow templates end-to-end through the NL Query runner.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException

from shieldops.agents.nl_query.models import NLQueryResponse
from shieldops.agents.nl_query.template_runner import (
    TemplateNotFoundError,
    run_template,
)
from shieldops.agents.nl_query.templates import list_templates
from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/query/nl/templates", tags=["NL Query Templates"])

# Injected at startup from app.py — kept module-level so tests can replace it.
_runner: Any = None


def set_runner(runner: Any) -> None:
    """Inject the NL Query runner used to execute templates."""
    global _runner
    _runner = runner


def _get_runner() -> Any:
    if _runner is None:
        raise HTTPException(status_code=503, detail="NL Query runner not initialized")
    return _runner


def _org(user: UserResponse) -> str:
    return (
        getattr(user, "org_id", None)
        or getattr(user, "tenant_id", None)
        or getattr(user, "id", "default")
    )


@router.get("")
async def list_soc_templates(
    user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List all registered SOC workflow templates."""
    return {"templates": list_templates()}


@router.post("/{template_id}/run", response_model=NLQueryResponse)
async def run_soc_template(
    template_id: str,
    user: UserResponse = Depends(get_current_user),
) -> NLQueryResponse:
    """Execute a named SOC template end-to-end via the NL Query runner."""
    runner = _get_runner()
    org_id = _org(user)
    try:
        return await run_template(template_id=template_id, org_id=org_id, runner=runner)
    except TemplateNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
