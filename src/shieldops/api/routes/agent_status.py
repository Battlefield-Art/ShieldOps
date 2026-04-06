"""Agent Status Monitor API — real-time status for the 10 launch agents.

Exposes three endpoints backing the Agent Status Monitor dashboard:

- ``GET /api/v1/agents/status``                     → list of launch agents with derived status
- ``GET /api/v1/agents/status/{agent_name}/history`` → last 10 runs for an agent
- ``GET /api/v1/agents/status/{agent_name}/connectors`` → connector dependencies + live health

Status is derived from the most recent runs in ``AgentRunRepository``:

- ``running`` — any of the last 3 runs is RUNNING or PENDING
- ``error``   — latest run is FAILED
- ``healthy`` — latest run is COMPLETED
- ``idle``    — no runs on record

Connector health is pulled from the :class:`HealthCheckRegistry` singleton.
Agents whose connectors are not registered return ``unknown`` status entries
so the UI can still render the dependency list without blowing up.

The router is mounted BEFORE the legacy ``/agents/{agent_id}`` route in
``app.py`` lifespan startup to avoid being shadowed — see
``tests/unit/api/test_agent_status.py::_build_app`` for the test equivalent.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user
from shieldops.api.auth.models import UserResponse
from shieldops.connectors.health import ConnectorStatus, HealthCheckRegistry
from shieldops.db.models_agent_run import AgentRunStatus
from shieldops.db.repositories.agent_run import AgentRunRepository

logger = structlog.get_logger()

router = APIRouter(prefix="/agents/status", tags=["Agent Status"])


# ── Launch agent configuration ──────────────────────────────────────

LAUNCH_AGENTS: list[str] = [
    "investigation",
    "remediation",
    "agent_firewall",
    "cost",
    "soc_analyst",
    "compliance_auditor",
    "vulnerability_manager",
    "identity_graph",
    "threat_hunter",
    "incident_response",
]

# Connector dependencies for each launch agent. Only names — health is
# resolved at request time against :class:`HealthCheckRegistry`.
AGENT_CONNECTOR_DEPS: dict[str, list[str]] = {
    "investigation": ["aws", "splunk", "datadog"],
    "remediation": ["aws", "kubernetes", "servicenow"],
    "agent_firewall": ["crowdstrike", "splunk"],
    "cost": ["aws", "gcp", "azure"],
    "soc_analyst": ["splunk", "crowdstrike", "pagerduty"],
    "compliance_auditor": ["aws", "servicenow", "jira"],
    "vulnerability_manager": ["wiz", "crowdstrike", "jira"],
    "identity_graph": ["aws", "azure", "crowdstrike"],
    "threat_hunter": ["splunk", "elastic", "crowdstrike"],
    "incident_response": ["pagerduty", "slack", "servicenow"],
}


# ── Repository injection ────────────────────────────────────────────

_run_repo: AgentRunRepository | None = None


def set_run_repository(repo: AgentRunRepository) -> None:
    """Inject the AgentRunRepository (called during app startup)."""
    global _run_repo
    _run_repo = repo


def _get_repository() -> AgentRunRepository:
    if _run_repo is None:
        raise HTTPException(status_code=503, detail="Agent run repository not initialized")
    return _run_repo


def _extract_org_id(user: UserResponse) -> str:
    return getattr(user, "org_id", None) or user.id


# ── Response models ─────────────────────────────────────────────────


class AgentRunSummary(BaseModel):
    """Minimal run payload used by the status dashboard."""

    id: str
    status: str
    duration_ms: int
    error_message: str | None = None
    created_at: datetime


class AgentStatusItem(BaseModel):
    """Status row for a single launch agent."""

    agent_name: str
    status: str = Field(description="running | healthy | error | idle")
    last_run: datetime | None = None
    success_rate: float = Field(ge=0.0, le=1.0)
    total_runs: int = Field(ge=0)
    recent_errors: list[str] = Field(default_factory=list)


class AgentStatusListResponse(BaseModel):
    agents: list[AgentStatusItem]


class AgentHistoryResponse(BaseModel):
    agent_name: str
    runs: list[AgentRunSummary]


class ConnectorHealthItem(BaseModel):
    name: str
    status: str = Field(description="healthy | degraded | unavailable | unknown")
    latency_ms: float = 0.0
    message: str = ""
    last_checked: datetime | None = None


class AgentConnectorsResponse(BaseModel):
    agent_name: str
    connectors: list[ConnectorHealthItem]


# ── Derivation helpers ──────────────────────────────────────────────


def _derive_status(runs: list[Any]) -> str:
    """Derive a status string from a sequence of runs (newest first)."""
    if not runs:
        return "idle"

    recent_three = runs[:3]
    for run in recent_three:
        if run.status in (AgentRunStatus.RUNNING, AgentRunStatus.PENDING):
            return "running"

    latest = runs[0]
    if latest.status == AgentRunStatus.FAILED:
        return "error"
    if latest.status == AgentRunStatus.COMPLETED:
        return "healthy"
    return "idle"


def _calc_success_rate(runs: list[Any]) -> float:
    terminal = [r for r in runs if r.status in (AgentRunStatus.COMPLETED, AgentRunStatus.FAILED)]
    if not terminal:
        return 0.0
    success = sum(1 for r in terminal if r.status == AgentRunStatus.COMPLETED)
    return round(success / len(terminal), 4)


def _collect_recent_errors(runs: list[Any], limit: int = 3) -> list[str]:
    errors: list[str] = []
    for run in runs:
        if run.status == AgentRunStatus.FAILED and run.error_message:
            errors.append(run.error_message)
            if len(errors) >= limit:
                break
    return errors


# ── Endpoints ───────────────────────────────────────────────────────


@router.get("", response_model=AgentStatusListResponse)
async def list_agent_status(
    user: UserResponse = Depends(get_current_user),
    repo: AgentRunRepository = Depends(_get_repository),
) -> AgentStatusListResponse:
    """Return derived status for every launch agent, scoped to the user's org."""
    org_id = _extract_org_id(user)
    items: list[AgentStatusItem] = []

    for agent_name in LAUNCH_AGENTS:
        runs, total = await repo.list_runs(
            agent_name=agent_name,
            org_id=org_id,
            page=1,
            limit=50,
        )
        items.append(
            AgentStatusItem(
                agent_name=agent_name,
                status=_derive_status(runs),
                last_run=runs[0].created_at if runs else None,
                success_rate=_calc_success_rate(runs),
                total_runs=total,
                recent_errors=_collect_recent_errors(runs),
            )
        )

    return AgentStatusListResponse(agents=items)


@router.get("/{agent_name}/history", response_model=AgentHistoryResponse)
async def get_agent_history(
    agent_name: str,
    user: UserResponse = Depends(get_current_user),
    repo: AgentRunRepository = Depends(_get_repository),
) -> AgentHistoryResponse:
    """Return the last 10 runs for a launch agent."""
    if agent_name not in LAUNCH_AGENTS:
        raise HTTPException(status_code=404, detail=f"Unknown launch agent: {agent_name}")

    org_id = _extract_org_id(user)
    runs, _ = await repo.list_runs(
        agent_name=agent_name,
        org_id=org_id,
        page=1,
        limit=10,
    )
    return AgentHistoryResponse(
        agent_name=agent_name,
        runs=[
            AgentRunSummary(
                id=r.id,
                status=r.status,
                duration_ms=r.duration_ms,
                error_message=r.error_message,
                created_at=r.created_at,
            )
            for r in runs
        ],
    )


@router.get("/{agent_name}/connectors", response_model=AgentConnectorsResponse)
async def get_agent_connectors(
    agent_name: str,
    user: UserResponse = Depends(get_current_user),
) -> AgentConnectorsResponse:
    """Return the connector dependencies for a launch agent with live health."""
    if agent_name not in LAUNCH_AGENTS:
        raise HTTPException(status_code=404, detail=f"Unknown launch agent: {agent_name}")

    registry = HealthCheckRegistry()
    registered = set(registry.registered_connectors)
    deps = AGENT_CONNECTOR_DEPS.get(agent_name, [])
    items: list[ConnectorHealthItem] = []

    for name in deps:
        if name not in registered:
            items.append(
                ConnectorHealthItem(
                    name=name,
                    status="unknown",
                    message="Connector not registered",
                )
            )
            continue
        try:
            health = await registry.check(name)
            items.append(
                ConnectorHealthItem(
                    name=name,
                    status=health.status.value
                    if isinstance(health.status, ConnectorStatus)
                    else str(health.status),
                    latency_ms=health.latency_ms,
                    message=health.message,
                    last_checked=health.last_checked,
                )
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "connector_health_lookup_failed",
                agent=agent_name,
                connector=name,
                error=str(exc),
            )
            items.append(
                ConnectorHealthItem(
                    name=name,
                    status="unavailable",
                    message=f"Health check error: {exc}",
                )
            )

    return AgentConnectorsResponse(agent_name=agent_name, connectors=items)
