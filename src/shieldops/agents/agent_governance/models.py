"""Agent Governance Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class GovernanceStage(StrEnum):
    DISCOVER_AGENTS = "discover_agents"
    ASSESS_CAPABILITIES = "assess_capabilities"
    ENFORCE_BOUNDARIES = "enforce_boundaries"
    EVALUATE_ESCALATIONS = "evaluate_escalations"
    AUDIT_COMPLIANCE = "audit_compliance"
    REPORT = "report"


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class EnforcementAction(StrEnum):
    ALLOW = "allow"
    RESTRICT = "restrict"
    BLOCK = "block"
    ESCALATE = "escalate"
    REVOKE = "revoke"


class AgentCapability(BaseModel):
    """A capability registered to an AI agent."""

    id: str = ""
    agent_id: str = ""
    capability_name: str = ""
    scope: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    approved: bool = False
    approved_by: str = ""
    expires_at: datetime | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class BoundaryViolation(BaseModel):
    """A detected boundary violation by an AI agent."""

    id: str = ""
    agent_id: str = ""
    violation_type: str = ""
    capability_attempted: str = ""
    action_taken: EnforcementAction = EnforcementAction.BLOCK
    severity: RiskLevel = RiskLevel.HIGH
    details: str = ""
    detected_at: datetime | None = None


class EscalationRecord(BaseModel):
    """An escalation triggered by governance policy."""

    id: str = ""
    agent_id: str = ""
    reason: str = ""
    escalated_to: str = ""
    resolved: bool = False
    resolution: str = ""
    created_at: datetime | None = None


class AgentGovernanceState(BaseModel):
    """Main state for the Agent Governance agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: GovernanceStage = GovernanceStage.DISCOVER_AGENTS

    # Discovered agents
    discovered_agents: list[dict[str, Any]] = Field(default_factory=list)
    total_agents: int = 0

    # Capabilities assessment
    capabilities: list[dict[str, Any]] = Field(default_factory=list)
    unauthorized_capabilities: int = 0

    # Boundary enforcement
    violations: list[dict[str, Any]] = Field(default_factory=list)
    enforcements_applied: int = 0

    # Escalations
    escalations: list[dict[str, Any]] = Field(default_factory=list)

    # Compliance
    compliance_score: float = 0.0
    policy_violations: int = 0

    # Report
    summary: str = ""
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
