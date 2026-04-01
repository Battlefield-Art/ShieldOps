"""State models for the Agent Trust Broker Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ------------------------------------------------


class ATBStage(StrEnum):
    """Workflow stages for agent trust brokering."""

    REGISTER_AGENTS = "register_agents"
    VALIDATE_IDENTITY = "validate_identity"
    ESTABLISH_TRUST = "establish_trust"
    MONITOR_BEHAVIOR = "monitor_behavior"
    REVOKE_COMPROMISED = "revoke_compromised"
    REPORT = "report"


class TrustLevel(StrEnum):
    """Trust level for an agent."""

    UNTRUSTED = "untrusted"
    PROVISIONAL = "provisional"
    VERIFIED = "verified"
    TRUSTED = "trusted"
    PRIVILEGED = "privileged"


class AgentVerificationStatus(StrEnum):
    """Verification status of an agent."""

    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    REVOKED = "revoked"
    EXPIRED = "expired"


# -- Domain Models -------------------------------------------


class AgentRegistration(BaseModel):
    """A registered agent."""

    agent_id: str = ""
    agent_type: str = ""
    capabilities: list[str] = Field(default_factory=list)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    registered_at: str = ""


class IdentityValidation(BaseModel):
    """Identity validation result."""

    agent_id: str = ""
    status: AgentVerificationStatus = AgentVerificationStatus.PENDING
    confidence: float = 0.0
    method: str = ""
    validated_at: str = ""


class TrustRelationship(BaseModel):
    """Trust relationship between agents."""

    source_agent: str = ""
    target_agent: str = ""
    trust_level: TrustLevel = TrustLevel.PROVISIONAL
    scope: list[str] = Field(default_factory=list)
    expires_at: str = ""


class BehaviorRecord(BaseModel):
    """Behavior monitoring record."""

    agent_id: str = ""
    anomaly_score: float = 0.0
    actions_observed: int = 0
    policy_violations: int = 0
    risk_level: str = "low"


class RevocationRecord(BaseModel):
    """Trust revocation record."""

    agent_id: str = ""
    reason: str = ""
    revoked_at: str = ""
    previous_trust: TrustLevel = TrustLevel.TRUSTED


# -- Reasoning + State ---------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class AgentTrustBrokerState(BaseModel):
    """Full state for the Agent Trust Broker."""

    request_id: str = ""
    tenant_id: str = ""
    stage: ATBStage = ATBStage.REGISTER_AGENTS
    config: dict[str, Any] = Field(default_factory=dict)

    registrations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    validations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    trust_relationships: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    behavior_records: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    revocations: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
