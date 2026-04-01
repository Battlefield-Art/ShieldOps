"""State models for the Deception Mesh Controller Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ------------------------------------------------


class DMCStage(StrEnum):
    """Workflow stages for deception mesh control."""

    PLAN_DEPLOYMENT = "plan_deployment"
    DEPLOY_DECOYS = "deploy_decoys"
    MONITOR_INTERACTIONS = "monitor_interactions"
    ANALYZE_ATTACKER = "analyze_attacker"
    CORRELATE_INTEL = "correlate_intel"
    REPORT = "report"


class DecoyType(StrEnum):
    """Type of deception asset."""

    HONEYPOT = "honeypot"
    HONEYTOKEN = "honeytoken"
    BREADCRUMB = "breadcrumb"
    HONEY_CREDENTIAL = "honey_credential"
    HONEY_SERVICE = "honey_service"


class InteractionSeverity(StrEnum):
    """Severity of decoy interaction."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    BENIGN = "benign"


# -- Domain Models -------------------------------------------


class DeploymentPlan(BaseModel):
    """Plan for decoy deployment."""

    plan_id: str = ""
    decoy_type: DecoyType = DecoyType.HONEYPOT
    target_network: str = ""
    placement_strategy: str = ""
    expected_coverage: float = 0.0


class DeployedDecoy(BaseModel):
    """A deployed deception asset."""

    decoy_id: str = ""
    decoy_type: DecoyType = DecoyType.HONEYPOT
    location: str = ""
    status: str = "active"
    deployed_at: str = ""


class InteractionRecord(BaseModel):
    """Record of interaction with a decoy."""

    interaction_id: str = ""
    decoy_id: str = ""
    source_ip: str = ""
    severity: InteractionSeverity = InteractionSeverity.MEDIUM
    timestamp: str = ""
    action_taken: str = ""


class AttackerProfile(BaseModel):
    """Profile of an attacker based on decoy interactions."""

    profile_id: str = ""
    source_ips: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    sophistication: str = "medium"
    intent: str = ""


class IntelCorrelation(BaseModel):
    """Correlation of deception intel with threat data."""

    correlation_id: str = ""
    profile_id: str = ""
    matched_campaigns: list[str] = Field(
        default_factory=list,
    )
    confidence: float = 0.0
    iocs: list[str] = Field(default_factory=list)


# -- Reasoning + State ---------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class DeceptionMeshControllerState(BaseModel):
    """Full state for the Deception Mesh Controller."""

    request_id: str = ""
    tenant_id: str = ""
    stage: DMCStage = DMCStage.PLAN_DEPLOYMENT
    config: dict[str, Any] = Field(default_factory=dict)

    deployment_plans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    deployed_decoys: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    interactions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    attacker_profiles: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    intel_correlations: list[dict[str, Any]] = Field(
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
