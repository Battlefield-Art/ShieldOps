"""API Rate Limiter API endpoints."""

from __future__ import annotations

import time
from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from shieldops.api.auth.dependencies import get_current_user, require_role
from shieldops.api.auth.models import UserResponse, UserRole

logger = structlog.get_logger()
router = APIRouter(prefix="/api-rate-limiter", tags=["API Rate Limiter"])

_runner: Any = None


def set_runner(runner: Any) -> None:
    """Set the API Rate Limiter runner instance."""
    global _runner
    _runner = runner


def _get_runner() -> Any:
    if _runner is None:
        raise HTTPException(
            status_code=501,
            detail="API Rate Limiter not configured",
        )
    return _runner


# --- Request models ---


class AnalyzeRequest(BaseModel):
    """Request to analyze API traffic for abuse patterns."""

    tenant_id: str = ""
    time_window_minutes: int = 5
    requests: list[dict[str, Any]] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


class CheckClientRequest(BaseModel):
    """Request to check if a client is rate-limited."""

    client_id: str = ""
    ip_address: str = ""
    endpoint: str = "/"

    model_config = {"extra": "forbid"}


class CreateRuleRequest(BaseModel):
    """Request to create a manual rate limit rule."""

    client_id: str = ""
    endpoint_pattern: str = "*"
    requests_per_minute: int = 60
    burst_limit: int = 100
    action: str = "throttle"
    reason: str = ""
    ttl_seconds: int = 3600

    model_config = {"extra": "forbid"}


# --- Routes ---


@router.get("/health")
async def rate_limiter_health() -> dict[str, Any]:
    """Health check for API Rate Limiter service."""
    return {
        "service": "api-rate-limiter",
        "status": "healthy" if _runner else "not_initialized",
        "timestamp": time.time(),
    }


@router.post("/analyze")
async def analyze_traffic(
    request: AnalyzeRequest,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Analyze API traffic for abuse patterns and enforce limits."""
    runner = _get_runner()
    result = await runner.analyze(
        requests=request.requests,
        context={
            "tenant_id": request.tenant_id,
            "time_window_minutes": request.time_window_minutes,
        },
    )
    return {
        "status": "completed",
        "summary": result.get("summary", {}),
        "abuse_detections": result.get("abuse_detections", []),
        "blocked_clients": result.get("blocked_clients", []),
        "throttled_clients": result.get("throttled_clients", []),
        "rules_applied": len(result.get("rate_limit_rules", [])),
    }


@router.post("/check")
async def check_client(
    request: CheckClientRequest,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Check if a client is currently rate-limited."""
    runner = _get_runner()
    return await runner.check_client(
        client_id=request.client_id,
        ip_address=request.ip_address,
        endpoint=request.endpoint,
    )


@router.get("/rules")
async def list_rules(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List all active rate limit rules."""
    runner = _get_runner()
    rules = runner._toolkit._rules
    return {
        "rules": [r.model_dump() for r in rules.values()],
        "count": len(rules),
    }


@router.post("/rules")
async def create_rule(
    request: CreateRuleRequest,
    _user: UserResponse = Depends(require_role(UserRole.ADMIN)),
) -> dict[str, Any]:
    """Create a manual rate limit rule. Requires ADMIN role."""
    import uuid

    from shieldops.agents.api_rate_limiter.models import (
        ActionType,
        RateLimitRule,
    )

    runner = _get_runner()

    rule = RateLimitRule(
        rule_id=f"manual-{uuid.uuid4().hex[:8]}",
        client_id=request.client_id,
        endpoint_pattern=request.endpoint_pattern,
        requests_per_minute=request.requests_per_minute,
        burst_limit=request.burst_limit,
        action=ActionType(request.action),
        reason=request.reason or "manual_rule",
        ttl_seconds=request.ttl_seconds,
        adaptive=False,
    )
    runner._toolkit._rules[rule.rule_id] = rule
    logger.info(
        "api_rate_limiter.rule_created",
        rule_id=rule.rule_id,
        client_id=request.client_id,
    )
    return {"status": "created", "rule": rule.model_dump()}


@router.get("/blocked")
async def list_blocked_clients(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List all currently blocked clients."""
    runner = _get_runner()
    summary = await runner._toolkit.get_enforcement_summary()
    return {
        "blocked_clients": summary["blocked_clients"],
        "throttled_clients": summary["throttled_clients"],
        "blocked_count": summary["blocked_count"],
        "throttled_count": summary["throttled_count"],
    }


@router.delete("/blocked/{client_id}")
async def unblock_client(
    client_id: str,
    _user: UserResponse = Depends(require_role(UserRole.ADMIN)),
) -> dict[str, Any]:
    """Unblock a client. Requires ADMIN role."""
    runner = _get_runner()
    runner._toolkit._blocked.discard(client_id)
    runner._toolkit._throttled.discard(client_id)
    logger.info(
        "api_rate_limiter.client_unblocked",
        client_id=client_id,
    )
    return {"client_id": client_id, "status": "unblocked"}


@router.get("/metrics")
async def get_metrics(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get rate limiter metrics."""
    runner = _get_runner()
    summary = await runner._toolkit.get_enforcement_summary()
    return {
        "service": "api-rate-limiter",
        "enforcement": summary,
        "timestamp": time.time(),
    }
