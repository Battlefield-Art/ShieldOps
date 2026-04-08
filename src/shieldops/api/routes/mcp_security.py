"""MCP Security API endpoints.

Provides REST endpoints for MCP ecosystem security scanning, God Key detection,
supply chain analysis, zero-trust compliance, and gateway policy management.
"""

import time
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field

from shieldops.agents.mcp_security.agent import MCPSecurityRunner
from shieldops.api.auth.dependencies import get_current_user, require_role
from shieldops.api.auth.models import UserResponse, UserRole

router = APIRouter()

# Application-level runner instance
_runner: MCPSecurityRunner | None = None


def get_runner() -> MCPSecurityRunner:
    """Get or create the MCP security runner singleton."""
    global _runner
    if _runner is None:
        _runner = MCPSecurityRunner()
    return _runner


def set_runner(runner: MCPSecurityRunner) -> None:
    """Override the runner instance (used for testing and dependency injection)."""
    global _runner
    _runner = runner


# --- Request models ---


class TriggerScanRequest(BaseModel):
    """Request body to trigger an MCP security scan."""

    endpoints: list[str] = Field(description="MCP server endpoints to scan")
    scan_depth: str = "standard"  # quick, standard, deep
    policy_set: dict[str, Any] = Field(default_factory=dict)


class CreatePolicyRequest(BaseModel):
    """Request body to create a gateway policy."""

    server_pattern: str = Field(description="Regex pattern matching server endpoints")
    allowed_agents: list[str] = Field(default_factory=list)
    auth_requirement: str = "oauth2"
    rate_limit_per_minute: int = 60
    max_data_bytes: int = 10_485_760
    allowed_tools: list[str] = Field(default_factory=list)
    blocked_tools: list[str] = Field(default_factory=list)


# --- Endpoints ---


@router.get("/mcp-security/health")
async def mcp_security_health() -> dict[str, Any]:
    """Health check for MCP Security service."""
    has_runner = _runner is not None
    components: dict[str, str] = {}
    if has_runner:
        components["gateway"] = "ok" if hasattr(_runner, "gateway") else "not_initialized"
        components["registry"] = "ok" if hasattr(_runner, "registry") else "not_initialized"
        components["zero_trust"] = "ok" if hasattr(_runner, "zero_trust") else "not_initialized"
    else:
        components["gateway"] = "not_initialized"
        components["registry"] = "not_initialized"
        components["zero_trust"] = "not_initialized"
    all_ok = all(v == "ok" for v in components.values())
    return {
        "service": "mcp-security",
        "status": "healthy" if all_ok else "degraded",
        "components": components,
        "timestamp": time.time(),
    }


@router.get("/mcp-security/servers")
async def list_mcp_servers(
    limit: int = 50,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List discovered MCP servers with risk scores."""
    runner = get_runner()
    connections = runner.registry.list_connections(limit=limit)
    servers = [
        {
            "server_id": c.server_id,
            "server_name": c.server_name,
            "endpoint": c.endpoint,
            "risk_score": c.risk_score,
            "status": c.status.value,
            "tools_exposed": c.tools_exposed,
            "downstream_count": len(c.downstream_resources),
            "owner": c.owner,
        }
        for c in connections
    ]
    return {"servers": servers, "total": len(servers)}


@router.get("/mcp-security/servers/{server_id}")
async def get_mcp_server(
    server_id: str,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get detailed info for a specific MCP server."""
    runner = get_runner()
    conn = runner.registry.get_connection(server_id)
    if conn is None:
        raise HTTPException(status_code=404, detail="MCP server not found")

    trust = runner.zero_trust.evaluate_trust(server_id)
    blast_radius = runner.registry.map_blast_radius(server_id)

    return {
        "server_id": conn.server_id,
        "server_name": conn.server_name,
        "endpoint": conn.endpoint,
        "risk_score": conn.risk_score,
        "status": conn.status.value,
        "tools_exposed": conn.tools_exposed,
        "downstream_resources": [r.model_dump() for r in conn.downstream_resources],
        "owner": conn.owner,
        "trust_evaluation": trust,
        "blast_radius": blast_radius,
    }


@router.post("/mcp-security/scan", status_code=202)
async def trigger_scan(
    request: TriggerScanRequest,
    background_tasks: BackgroundTasks,
    _user: UserResponse = Depends(require_role(UserRole.ADMIN, UserRole.OPERATOR)),
) -> dict[str, Any]:
    """Trigger an MCP security scan. Runs asynchronously."""
    runner = get_runner()

    background_tasks.add_task(
        runner.scan,
        endpoints=request.endpoints,
        context={
            "scan_depth": request.scan_depth,
            "policy_set": request.policy_set,
        },
    )

    return {
        "status": "accepted",
        "scan_depth": request.scan_depth,
        "endpoint_count": len(request.endpoints),
        "message": "MCP security scan started. Use GET /mcp-security/metrics to track progress.",
    }


@router.get("/mcp-security/god-keys")
async def list_god_keys(
    max_downstream: int = 5,
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """List MCP servers with God Key risk (excessive downstream access)."""
    runner = get_runner()
    god_keys = runner.registry.detect_god_keys(max_downstream=max_downstream)
    return {
        "god_keys": god_keys,
        "total": len(god_keys),
        "threshold": max_downstream,
    }


@router.get("/mcp-security/supply-chain")
async def get_supply_chain(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get supply chain scan results."""
    runner = get_runner()
    report = runner.supply_chain.generate_supply_chain_report()
    return report.model_dump()


@router.get("/mcp-security/zero-trust")
async def get_zero_trust_compliance(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get zero-trust compliance dashboard for MCP servers."""
    runner = get_runner()
    report = runner.zero_trust.generate_zero_trust_report()
    return report.model_dump()


@router.post("/mcp-security/policies")
async def create_gateway_policy(
    request: CreatePolicyRequest,
    _user: UserResponse = Depends(require_role(UserRole.ADMIN, UserRole.OPERATOR)),
) -> dict[str, Any]:
    """Create a gateway policy for MCP server traffic."""
    from shieldops.security.mcp_security_gateway import AuthRequirement

    runner = get_runner()

    try:
        auth_req = AuthRequirement(request.auth_requirement)
    except ValueError:
        auth_req = AuthRequirement.OAUTH2

    policy = runner.gateway.add_policy(
        server_pattern=request.server_pattern,
        allowed_agents=request.allowed_agents,
        auth_requirement=auth_req,
        rate_limit_per_minute=request.rate_limit_per_minute,
        max_data_bytes=request.max_data_bytes,
        allowed_tools=request.allowed_tools,
        blocked_tools=request.blocked_tools,
    )

    return {
        "policy_id": policy.id,
        "server_pattern": policy.server_pattern,
        "auth_requirement": policy.auth_requirement.value,
        "status": "created",
    }


@router.get("/mcp-security/metrics")
async def get_mcp_security_metrics(
    _user: UserResponse = Depends(get_current_user),
) -> dict[str, Any]:
    """Get MCP security metrics and scan summaries."""
    runner = get_runner()

    gateway_stats = runner.gateway.get_stats()
    supply_chain_stats = runner.supply_chain.get_stats()
    zero_trust_stats = runner.zero_trust.get_stats()
    registry_stats = runner.registry.get_stats()
    scans = runner.list_scans()

    return {
        "gateway": gateway_stats,
        "supply_chain": supply_chain_stats,
        "zero_trust": zero_trust_stats,
        "registry": registry_stats,
        "scans": {
            "total": len(scans),
            "recent": scans[-5:] if scans else [],
        },
    }
