"""State models for the MCP Gateway Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class GatewayStage(StrEnum):
    """Stages of the MCP Gateway workflow."""

    DISCOVER_SERVERS = "discover_servers"
    ASSESS_SECURITY = "assess_security"
    ENFORCE_POLICIES = "enforce_policies"
    MONITOR_TRAFFIC = "monitor_traffic"
    DETECT_ABUSE = "detect_abuse"
    REPORT = "report"


class AuthMethod(StrEnum):
    """Supported authentication methods for MCP servers."""

    OAUTH2 = "oauth2"
    API_KEY = "api_key"
    MTLS = "mtls"
    NONE = "none"
    CUSTOM = "custom"


class MCPServerRisk(StrEnum):
    """Risk classification for an MCP server."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SECURE = "secure"


class MCPServerProfile(BaseModel):
    """Profile of a discovered MCP server behind the gateway."""

    id: str = ""
    server_name: str = ""
    endpoint_url: str = ""
    auth_method: AuthMethod = AuthMethod.NONE
    tools_exposed: list[str] = Field(default_factory=list)
    permission_scope: str = ""
    tls_enabled: bool = False
    rate_limit_configured: bool = False
    god_key_risk: bool = False
    risk_level: MCPServerRisk = MCPServerRisk.MEDIUM
    last_audited: float = 0.0


class SecurityAssessment(BaseModel):
    """Security assessment for an MCP server."""

    id: str = ""
    server_id: str = ""
    vulnerabilities: list[str] = Field(default_factory=list)
    missing_controls: list[str] = Field(default_factory=list)
    god_key_detected: bool = False
    risk_score: float = 0.0
    remediation_steps: list[str] = Field(default_factory=list)


class PolicyEnforcement(BaseModel):
    """Record of a gateway policy enforcement action."""

    id: str = ""
    server_id: str = ""
    policy_name: str = ""
    action: str = "log"  # enforce | warn | log
    target: str = ""
    applied: bool = False
    success: bool = False


class TrafficAnomaly(BaseModel):
    """A detected traffic anomaly for an MCP server."""

    id: str = ""
    server_id: str = ""
    anomaly_type: str = ""
    tool_name: str = ""
    caller_id: str = ""
    request_count: int = 0
    time_window_min: int = 0
    blocked: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step: int = 0
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class MCPGatewayState(BaseModel):
    """Full state of the MCP Gateway Agent workflow (LangGraph state)."""

    # Input
    request_id: str = ""
    stage: GatewayStage = GatewayStage.DISCOVER_SERVERS
    tenant_id: str = ""

    # Discovery & assessment
    mcp_servers: list[MCPServerProfile] = Field(default_factory=list)
    security_assessments: list[SecurityAssessment] = Field(
        default_factory=list,
    )
    policy_enforcements: list[PolicyEnforcement] = Field(
        default_factory=list,
    )
    traffic_anomalies: list[TrafficAnomaly] = Field(default_factory=list)
    god_keys_found: int = 0

    # Aggregated stats
    stats: dict[str, Any] = Field(default_factory=dict)

    # Metadata
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    session_start: float = 0.0
    session_duration_ms: int = 0
    error: str | None = None
