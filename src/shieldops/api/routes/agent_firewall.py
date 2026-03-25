"""Agent Behavioral Firewall API endpoints."""

from __future__ import annotations

import time
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user, require_role
from shieldops.api.auth.models import UserResponse, UserRole

logger = structlog.get_logger()
router = APIRouter(prefix="/agent-firewall", tags=["Agent Firewall"])

_firewall: Any = None
_interceptor: Any = None
_baseline: Any = None


def set_firewall(fw: Any) -> None:
    global _firewall
    _firewall = fw


def set_interceptor(ic: Any) -> None:
    global _interceptor
    _interceptor = ic


def set_baseline(bl: Any) -> None:
    global _baseline
    _baseline = bl


# --- Request models ---


class EvaluateCallRequest(BaseModel):
    tool_name: str = ""
    args: dict[str, Any] = Field(default_factory=dict)
    data_volume: float = 0.0


class CreatePolicyRequest(BaseModel):
    tool_pattern: str = "*"
    max_calls_per_minute: float = 60.0
    max_data_bytes: int = 1_000_000
    required_approval: bool = False
    allowed_hours: list[int] = Field(default_factory=lambda: list(range(0, 24)))


# --- Routes ---


@router.get("/health")
async def firewall_health() -> dict[str, Any]:
    """Health check for Agent Firewall service."""
    components = {
        "firewall_engine": "ok" if _firewall else "not_initialized",
        "interceptor": "ok" if _interceptor else "not_initialized",
        "baseline": "ok" if _baseline else "not_initialized",
    }
    all_ok = all(v == "ok" for v in components.values())
    return {
        "service": "agent-firewall",
        "status": "healthy" if all_ok else "degraded",
        "components": components,
        "timestamp": time.time(),
    }


@router.get("/agents")
async def list_monitored_agents(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List all monitored agents with their current status."""
    if _firewall is None:
        raise HTTPException(status_code=501, detail="Agent firewall not configured")
    stats = _firewall.get_stats()
    events = _firewall.list_events(limit=200)
    agents: dict[str, dict[str, Any]] = {}
    for e in events:
        aid = e.agent_id
        if aid not in agents:
            agents[aid] = {"agent_id": aid, "event_count": 0, "blocked": 0, "flagged": 0}
        agents[aid]["event_count"] += 1
        if e.action_taken.value == "block":
            agents[aid]["blocked"] += 1
        elif e.action_taken.value == "flag":
            agents[aid]["flagged"] += 1
    return {"agents": list(agents.values()), "total_agents": len(agents), **stats}


@router.get("/agents/{agent_id}/events")
async def get_agent_events(
    agent_id: str,
    limit: int = 50,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get event stream for a monitored agent."""
    if _firewall is None:
        raise HTTPException(status_code=501, detail="Agent firewall not configured")
    events = _firewall.list_events(agent_id=agent_id, limit=limit)
    return {
        "agent_id": agent_id,
        "events": [e.model_dump() for e in events],
        "count": len(events),
    }


@router.get("/agents/{agent_id}/baseline")
async def get_agent_baseline(
    agent_id: str,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get behavioral baseline for an agent."""
    if _baseline is None:
        raise HTTPException(status_code=501, detail="Baseline engine not configured")
    profile = _baseline.get_agent_profile(agent_id)
    return profile


@router.get("/agents/{agent_id}/audit-report")
async def get_agent_audit_report(
    agent_id: str,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get downloadable audit report for an agent."""
    if _interceptor is None:
        raise HTTPException(status_code=501, detail="Interceptor not configured")
    report = _interceptor.generate_audit_report(agent_id)
    return report


@router.post("/agents/{agent_id}/evaluate")
async def evaluate_tool_call(
    agent_id: str,
    request: EvaluateCallRequest,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Evaluate a tool call against firewall policies."""
    if _firewall is None:
        raise HTTPException(status_code=501, detail="Agent firewall not configured")
    result = _firewall.evaluate_call(
        agent_id=agent_id,
        tool_name=request.tool_name,
        args_summary=str(request.args),
        data_volume=request.data_volume,
    )
    return {"agent_id": agent_id, **result}


@router.post("/policies")
async def create_policy(
    request: CreatePolicyRequest,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Create a new firewall interception policy."""
    if _interceptor is None:
        raise HTTPException(status_code=501, detail="Interceptor not configured")
    policy = _interceptor.add_policy(
        tool_pattern=request.tool_pattern,
        max_rate=request.max_calls_per_minute,
        max_data=request.max_data_bytes,
        required_approval=request.required_approval,
        allowed_hours=request.allowed_hours,
    )
    return {"status": "created", "policy": policy.model_dump()}


@router.get("/policies")
async def list_policies(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List all firewall policies."""
    if _interceptor is None:
        raise HTTPException(status_code=501, detail="Interceptor not configured")
    policies = _interceptor.list_policies()
    return {"policies": [p.model_dump() for p in policies], "count": len(policies)}


@router.post("/agents/{agent_id}/kill-switch")
async def trigger_kill_switch(
    agent_id: str,
    _user: UserResponse = Depends(require_role(UserRole.ADMIN)),
) -> dict[str, Any]:
    """Trigger emergency kill switch for an agent. Requires ADMIN role."""
    if _firewall is None:
        raise HTTPException(status_code=501, detail="Agent firewall not configured")
    from shieldops.security.agent_behavioral_firewall import FirewallAction

    _firewall.record_event(
        agent_id=agent_id,
        tool_name="*",
        action=FirewallAction.KILL_SWITCH,
        risk_score=1.0,
        anomaly_type="manual_kill_switch",
    )
    logger.warning("agent_firewall.kill_switch_triggered", agent_id=agent_id)
    return {"agent_id": agent_id, "status": "kill_switch_activated"}


@router.get("/metrics")
async def get_firewall_metrics(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get firewall-wide metrics."""
    result: dict[str, Any] = {}
    if _firewall is not None:
        result["firewall"] = _firewall.get_stats()
        result["firewall_report"] = _firewall.generate_report().model_dump()
    if _interceptor is not None:
        result["interceptor"] = _interceptor.get_stats()
    if _baseline is not None:
        result["baseline"] = _baseline.get_stats()
    if not result:
        raise HTTPException(status_code=501, detail="No firewall components configured")
    return result
