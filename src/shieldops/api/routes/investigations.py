"""Investigation API endpoints.

Provides REST endpoints for triggering, tracking, and managing
investigation agent workflows.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
)
from pydantic import BaseModel, Field

from shieldops.agents.investigation.runner import InvestigationRunner
from shieldops.api.auth.dependencies import get_current_user, require_role
from shieldops.api.auth.models import UserResponse, UserRole
from shieldops.db.services import get_service
from shieldops.db.services.investigation_timeline import InvestigationTimelineService
from shieldops.models.base import AlertContext

router = APIRouter()

# Application-level runner instance (initialized on first use or at startup)
_runner: InvestigationRunner | None = None
_repository: Any | None = None


def get_runner() -> InvestigationRunner:
    """Get or create the investigation runner singleton."""
    global _runner
    if _runner is None:
        _runner = InvestigationRunner()
    return _runner


def set_runner(runner: InvestigationRunner) -> None:
    """Override the runner instance (used for testing and dependency injection)."""
    global _runner
    _runner = runner


def set_repository(repo: Any | None) -> None:
    """Set the persistence repository for read queries."""
    global _repository
    _repository = repo


# --- Request/Response models ---


class TriggerInvestigationRequest(BaseModel):
    """Request body to trigger a new investigation."""

    alert_id: str
    alert_name: str
    severity: str = "warning"
    source: str = "api"
    resource_id: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    description: str | None = None


class InvestigationSummary(BaseModel):
    """Brief investigation summary for list responses."""

    investigation_id: str
    alert_id: str
    alert_name: str
    status: str
    confidence: float
    hypotheses_count: int
    duration_ms: int
    error: str | None = None


# --- Endpoints ---


@router.post("/investigations", status_code=202)
async def trigger_investigation(
    request: TriggerInvestigationRequest,
    background_tasks: BackgroundTasks,
    _user: UserResponse = Depends(require_role(UserRole.ADMIN, UserRole.OPERATOR)),
) -> dict[str, Any]:
    """Trigger a new investigation for an alert.

    The investigation runs asynchronously. Returns immediately with a 202
    and the investigation can be tracked via the list/detail endpoints.
    """
    alert = AlertContext(
        alert_id=request.alert_id,
        alert_name=request.alert_name,
        severity=request.severity,
        source=request.source,
        resource_id=request.resource_id,
        labels=request.labels,
        annotations=request.annotations,
        triggered_at=datetime.now(UTC),
        description=request.description,
    )

    runner = get_runner()

    # Run investigation in background so the API responds immediately
    background_tasks.add_task(runner.investigate, alert)

    return {
        "status": "accepted",
        "alert_id": request.alert_id,
        "message": "Investigation started. Use GET /investigations to track progress.",
    }


@router.post("/investigations/sync")
async def trigger_investigation_sync(
    request: TriggerInvestigationRequest,
    _user: UserResponse = Depends(require_role(UserRole.ADMIN, UserRole.OPERATOR)),
) -> dict[str, Any]:
    """Trigger an investigation and wait for completion.

    Useful for testing and CLI tools. For production use, prefer the
    async POST /investigations endpoint.
    """
    alert = AlertContext(
        alert_id=request.alert_id,
        alert_name=request.alert_name,
        severity=request.severity,
        source=request.source,
        resource_id=request.resource_id,
        labels=request.labels,
        annotations=request.annotations,
        triggered_at=datetime.now(UTC),
        description=request.description,
    )

    runner = get_runner()
    result = await runner.investigate(alert)
    return result.model_dump(mode="json")


@router.get("/investigations")
async def list_investigations(
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List active and recent investigations.

    Queries from PostgreSQL when available, falls back to in-memory.
    """
    if _repository:
        items = await _repository.list_investigations(status=status, limit=limit, offset=offset)
        total = await _repository.count_investigations(status=status)
        return {
            "investigations": items,
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    # Fallback to in-memory
    runner = get_runner()
    all_investigations = runner.list_investigations()
    if status:
        all_investigations = [inv for inv in all_investigations if inv["status"] == status]
    total = len(all_investigations)
    paginated = all_investigations[offset : offset + limit]
    return {
        "investigations": paginated,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/investigations/{investigation_id}")
async def get_investigation(
    investigation_id: str,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get full investigation detail including reasoning chain and evidence."""
    if _repository:
        db_result = await _repository.get_investigation(investigation_id)
        if db_result is not None:
            return db_result

    runner = get_runner()
    state = runner.get_investigation(investigation_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return state.model_dump(mode="json")


@router.get("/investigations/{investigation_id}/timeline")
async def get_investigation_timeline(
    investigation_id: str,
    event_type: str | None = Query(
        None,
        description="Filter by event type",
    ),
    timeline_svc: InvestigationTimelineService = Depends(  # noqa: B008
        get_service(InvestigationTimelineService),
    ),
    _user: Any = Depends(
        require_role(UserRole.VIEWER, UserRole.OPERATOR, UserRole.ADMIN),
    ),
) -> dict[str, Any]:
    """Get unified timeline for an investigation.

    Merges investigation, remediation, and audit events into a single
    chronological timeline. Powered by ``InvestigationTimelineService``
    (RFC #245 PR-4) — the named service that replaced the deleted
    ``Repository.get_investigation_timeline``. Wired via FastAPI
    ``Depends(get_service(...))`` rather than the old
    ``app.state.repository`` god object.
    """
    if event_type:
        events = await timeline_svc.filter_by_type(investigation_id, event_type)
    else:
        events = await timeline_svc.build_timeline(investigation_id)

    if not events:
        # Empty either because the investigation doesn't exist or has no events.
        # Distinguish via a quick fetch; both cases now reach here.
        raise HTTPException(
            status_code=404,
            detail="Investigation not found or has no timeline events",
        )

    return {
        "investigation_id": investigation_id,
        "events": events,
        "total": len(events),
    }
