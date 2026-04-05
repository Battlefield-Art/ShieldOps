"""Agent execution run and audit trail API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse
from shieldops.db.repositories.agent_run import AgentRunRepository
from shieldops.db.repositories.audit_entry import AuditEntryRepository

logger = structlog.get_logger()

router = APIRouter(tags=["Agent Runs"])

_run_repo: AgentRunRepository | None = None
_audit_repo: AuditEntryRepository | None = None


def set_run_repository(repo: AgentRunRepository) -> None:
    """Inject the AgentRunRepository (called during app startup)."""
    global _run_repo
    _run_repo = repo


def set_audit_repository(repo: AuditEntryRepository) -> None:
    """Inject the AuditEntryRepository (called during app startup)."""
    global _audit_repo
    _audit_repo = repo


def _get_run_repo() -> AgentRunRepository:
    if _run_repo is None:
        raise HTTPException(status_code=503, detail="Agent run repository not initialized")
    return _run_repo


def _get_audit_repo() -> AuditEntryRepository:
    if _audit_repo is None:
        raise HTTPException(status_code=503, detail="Audit repository not initialized")
    return _audit_repo


# ── Response models ───────────────────────────────────────────────────


class AgentRunResponse(BaseModel):
    """Serialized agent run for API responses."""

    id: str
    agent_name: str
    status: str
    input_data: dict[str, Any]
    output_data: dict[str, Any]
    error_message: str | None
    duration_ms: int
    token_usage: dict[str, Any]
    org_id: str
    created_at: datetime
    updated_at: datetime


class PaginatedRunsResponse(BaseModel):
    runs: list[AgentRunResponse]
    total: int
    page: int
    limit: int


class AuditEntryResponse(BaseModel):
    """Serialized audit entry for API responses."""

    id: str
    action: str
    actor: str
    target: str
    result: str
    metadata: dict[str, Any]
    org_id: str
    created_at: datetime


class PaginatedAuditResponse(BaseModel):
    entries: list[AuditEntryResponse]
    total: int
    page: int
    limit: int


# ── Helpers ───────────────────────────────────────────────────────────


def _run_to_response(run: Any) -> AgentRunResponse:
    return AgentRunResponse(
        id=run.id,
        agent_name=run.agent_name,
        status=run.status,
        input_data=run.input_data,
        output_data=run.output_data,
        error_message=run.error_message,
        duration_ms=run.duration_ms,
        token_usage=run.token_usage,
        org_id=run.org_id,
        created_at=run.created_at,
        updated_at=run.updated_at,
    )


def _entry_to_response(entry: Any) -> AuditEntryResponse:
    return AuditEntryResponse(
        id=entry.id,
        action=entry.action,
        actor=entry.actor,
        target=entry.target,
        result=entry.result,
        metadata=entry.metadata_,
        org_id=entry.org_id,
        created_at=entry.created_at,
    )


def _extract_org_id(user: UserResponse) -> str:
    """Extract org_id from user context.

    In production, org_id comes from JWT claims or tenant isolation middleware.
    Falls back to user ID for single-tenant / dev scenarios.
    """
    return getattr(user, "org_id", None) or user.id


# ── Agent Run Endpoints ───────────────────────────────────────────────


@router.get("/{agent_name}/runs", response_model=PaginatedRunsResponse)
async def list_agent_runs(
    agent_name: str,
    status: str | None = Query(None, description="Filter by run status"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    user: UserResponse = Depends(get_current_user),
) -> PaginatedRunsResponse:
    """List paginated runs for a specific agent, scoped to the user's org."""
    repo = _get_run_repo()
    org_id = _extract_org_id(user)
    runs, total = await repo.list_runs(
        agent_name=agent_name,
        org_id=org_id,
        status=status,
        page=page,
        limit=limit,
    )
    return PaginatedRunsResponse(
        runs=[_run_to_response(r) for r in runs],
        total=total,
        page=page,
        limit=limit,
    )


@router.get("/{agent_name}/runs/{run_id}", response_model=AgentRunResponse)
async def get_agent_run(
    agent_name: str,
    run_id: str,
    user: UserResponse = Depends(get_current_user),
) -> AgentRunResponse:
    """Get a single run detail, scoped to the user's org."""
    repo = _get_run_repo()
    org_id = _extract_org_id(user)
    run = await repo.get_run(run_id)
    if run is None or run.org_id != org_id or run.agent_name != agent_name:
        raise HTTPException(status_code=404, detail="Run not found")
    return _run_to_response(run)


# ── Audit Log Endpoints ──────────────────────────────────────────────


@router.get("/audit", response_model=PaginatedAuditResponse)
async def list_audit_entries(
    action: str | None = Query(None, description="Filter by action"),
    actor: str | None = Query(None, description="Filter by actor"),
    result: str | None = Query(None, description="Filter by result"),
    start_date: datetime | None = Query(None, description="Start of date range (ISO 8601)"),
    end_date: datetime | None = Query(None, description="End of date range (ISO 8601)"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=200, description="Page size"),
    user: UserResponse = Depends(get_current_user),
) -> PaginatedAuditResponse:
    """List paginated audit entries, scoped to the user's org."""
    repo = _get_audit_repo()
    org_id = _extract_org_id(user)
    entries, total = await repo.list_entries(
        org_id=org_id,
        action=action,
        actor=actor,
        result=result,
        start_date=start_date,
        end_date=end_date,
        page=page,
        limit=limit,
    )
    return PaginatedAuditResponse(
        entries=[_entry_to_response(e) for e in entries],
        total=total,
        page=page,
        limit=limit,
    )
