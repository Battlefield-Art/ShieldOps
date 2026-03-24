"""State models for the Identity Graph Agent."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class IdentityNode(BaseModel):
    """A node in the identity graph representing a principal."""

    identity_id: str
    identity_name: str = ""
    identity_type: str = "human"  # human, service_account, ai_agent, federated
    provider: str = ""  # azure_ad, okta, gcp_iam, aws_iam, kubernetes
    permissions: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    mfa_enabled: bool = False
    last_active_at: datetime | None = None
    risk_score: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class TrustRelationship(BaseModel):
    """A trust relationship between two identity nodes."""

    source_id: str
    target_id: str
    relationship_type: str = "oauth_delegation"
    trust_level: float = Field(default=0.5, ge=0.0, le=1.0)
    scope: str = ""
    is_transitive: bool = False
    expires_at: datetime | None = None


class RiskAssessment(BaseModel):
    """Risk assessment for an identity or relationship."""

    entity_id: str
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    risk_factors: list[str] = Field(default_factory=list)
    recommended_action: str = "monitor"
    evidence: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class IdentityGraphState(BaseModel):
    """Full state of an identity graph scanning workflow."""

    # Input
    scan_target: str = ""
    identity_types: list[str] = Field(
        default_factory=lambda: ["human", "service_account", "ai_agent"]
    )
    scope: dict[str, Any] = Field(default_factory=dict)

    # Graph discovery
    identities_discovered: list[IdentityNode] = Field(default_factory=list)
    relationships_mapped: list[TrustRelationship] = Field(default_factory=list)
    trust_chains: list[list[str]] = Field(default_factory=list)
    risk_assessments: list[RiskAssessment] = Field(default_factory=list)

    # Findings
    over_privileged_identities: list[dict[str, Any]] = Field(default_factory=list)
    stale_grants: list[dict[str, Any]] = Field(default_factory=list)
    lateral_movement_paths: list[list[str]] = Field(default_factory=list)
    credential_risks: list[dict[str, Any]] = Field(default_factory=list)

    # Response
    remediation_actions: list[dict[str, Any]] = Field(default_factory=list)
    policy_updates: list[dict[str, Any]] = Field(default_factory=list)

    # Workflow
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str | None = None
