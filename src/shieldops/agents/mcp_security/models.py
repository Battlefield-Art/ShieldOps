"""State models for the MCP Security Agent."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class MCPServerInfo(BaseModel):
    """Discovered MCP server information."""

    endpoint: str = ""
    name: str = ""
    version: str = ""
    transport: str = "http_sse"
    auth_type: str = "none"
    tools_exposed: list[str] = Field(default_factory=list)
    downstream_resources: list[str] = Field(default_factory=list)
    risk_score: float = 0.0


class MCPVulnerability(BaseModel):
    """A vulnerability found in an MCP server configuration."""

    server_id: str = ""
    vuln_type: str = ""
    severity: str = "medium"
    description: str = ""
    remediation: str = ""


class GodKeyRisk(BaseModel):
    """A server identified as having God Key risk."""

    server_id: str = ""
    credential_scope: str = ""
    downstream_count: int = 0
    blast_radius: str = "unknown"
    sensitive_resources: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class MCPSecurityState(BaseModel):
    """Full state of an MCP security scan workflow (LangGraph state)."""

    # Input
    scan_id: str = ""
    scan_scope: list[str] = Field(default_factory=list)
    policy_set: dict[str, Any] = Field(default_factory=dict)
    scan_depth: str = "standard"  # quick, standard, deep

    # Discovery
    mcp_servers_found: list[MCPServerInfo] = Field(default_factory=list)
    connections_mapped: list[dict[str, Any]] = Field(default_factory=list)
    permissions_analyzed: list[dict[str, Any]] = Field(default_factory=list)

    # Vulnerabilities
    config_vulnerabilities: list[MCPVulnerability] = Field(default_factory=list)
    supply_chain_risks: list[dict[str, Any]] = Field(default_factory=list)
    excessive_permissions: list[dict[str, Any]] = Field(default_factory=list)
    god_key_risks: list[GodKeyRisk] = Field(default_factory=list)

    # Response
    policies_generated: list[dict[str, Any]] = Field(default_factory=list)
    remediations_applied: list[dict[str, Any]] = Field(default_factory=list)
    alerts_created: list[dict[str, Any]] = Field(default_factory=list)

    # Metadata
    scan_start: datetime | None = None
    scan_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
