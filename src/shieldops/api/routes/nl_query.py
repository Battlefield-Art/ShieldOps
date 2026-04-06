"""Natural Language Query API routes — English → SQL → security results."""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException

from shieldops.agents.nl_query import (
    NLQueryRequest,
    NLQueryResponse,
    NLQueryRunner,
)
from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse

logger = structlog.get_logger()

router = APIRouter(prefix="/query", tags=["Natural Language Query"])

_runner: NLQueryRunner | None = None


def set_runner(runner: NLQueryRunner) -> None:
    """Inject the NL query runner (called during app startup)."""
    global _runner
    _runner = runner


def _get_runner() -> NLQueryRunner:
    if _runner is None:
        raise HTTPException(status_code=503, detail="NL query runner not initialized")
    return _runner


@router.get("/health")
async def health() -> dict[str, Any]:
    """Health check for the NL query agent."""
    return {
        "status": "ok" if _runner is not None else "uninitialized",
        "agent": "nl_query",
    }


@router.post("/nl", response_model=NLQueryResponse)
async def natural_language_query(
    request: NLQueryRequest,
    user: UserResponse = Depends(get_current_user),
) -> NLQueryResponse:
    """Execute a natural language query against the security event store.

    Accepts an English question and an optional time range, generates a safe
    SELECT statement, executes it with tenant isolation enforced, and returns
    a formatted response (markdown + summary + rows).
    """
    runner = _get_runner()
    org_id = getattr(user, "org_id", user.id)

    logger.info(
        "nl_query.request",
        user=user.id,
        org_id=org_id,
        question=request.question[:200],
    )

    response = await runner.run(request, org_id=org_id)
    if response.error:
        logger.warning("nl_query.error", error=response.error, user=user.id)
    return response


@router.get("/nl/history", response_model=list[NLQueryResponse])
async def query_history(
    user: UserResponse = Depends(get_current_user),
) -> list[NLQueryResponse]:
    """Return the recent query history for the current user's org."""
    runner = _get_runner()
    _ = user  # Auth gate only — in-memory history is process-wide for now.
    return runner.get_history()
