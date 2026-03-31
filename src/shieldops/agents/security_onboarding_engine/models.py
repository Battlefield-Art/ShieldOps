"""State models for the Security Onboarding Engine Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class SOEStage(StrEnum):
    """Stages in the security onboarding lifecycle."""

    INTAKE_SERVICE = "intake_service"
    ASSESS_RISK_PROFILE = "assess_risk_profile"
    GENERATE_REQUIREMENTS = "generate_requirements"
    PROVISION_CONTROLS = "provision_controls"
    VALIDATE = "validate"
    REPORT = "report"


class ServiceTier(StrEnum):
    """Service tier classifications for risk profiling."""

    CRITICAL = "critical"
    HIGH = "high"
    STANDARD = "standard"
    LOW = "low"
    INTERNAL = "internal"


class DataClassification(StrEnum):
    """Data classification levels."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PII = "pii"
    PHI = "phi"


# --- Domain models ---


class ServiceIntake(BaseModel):
    """Intake record for a new service."""

    service_id: str = ""
    service_name: str = ""
    team: str = ""
    owner: str = ""
    environment: str = "production"
    tier: ServiceTier = ServiceTier.STANDARD
    data_classification: DataClassification = DataClassification.INTERNAL
    tech_stack: list[str] = Field(default_factory=list)
    external_facing: bool = False


class RiskProfile(BaseModel):
    """Risk profile assessment for a service."""

    service_id: str = ""
    risk_score: float = 0.0
    risk_level: str = "medium"
    data_sensitivity: str = ""
    attack_surface: str = ""
    compliance_requirements: list[str] = Field(
        default_factory=list,
    )
    threat_vectors: list[str] = Field(default_factory=list)


class SecurityRequirement(BaseModel):
    """A generated security requirement."""

    requirement_id: str = ""
    category: str = ""
    title: str = ""
    description: str = ""
    priority: str = "medium"
    mandatory: bool = True
    control_type: str = ""


class ProvisionedControl(BaseModel):
    """A provisioned security control."""

    control_id: str = ""
    requirement_id: str = ""
    control_type: str = ""
    status: str = "pending"
    provisioned_at: datetime | None = None
    configuration: dict[str, Any] = Field(
        default_factory=dict,
    )


class ValidationResult(BaseModel):
    """Validation result for onboarding controls."""

    service_id: str = ""
    total_controls: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    compliance_met: bool = False
    gaps: list[str] = Field(default_factory=list)


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the onboarding workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityOnboardingEngineState(BaseModel):
    """Full state for a security onboarding engine run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SOEStage = SOEStage.INTAKE_SERVICE

    # Inputs
    service_name: str = ""
    team: str = ""
    owner: str = ""
    environment: str = "production"
    tier: ServiceTier = ServiceTier.STANDARD
    data_classification: DataClassification = DataClassification.INTERNAL
    tech_stack: list[str] = Field(default_factory=list)
    external_facing: bool = False

    # Pipeline fields
    intake: dict[str, Any] = Field(default_factory=dict)
    risk_profile: dict[str, Any] = Field(
        default_factory=dict,
    )
    requirements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    controls: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    validation: dict[str, Any] = Field(
        default_factory=dict,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_requirements: int = 0
    controls_provisioned: int = 0
    controls_passed: int = 0
    controls_failed: int = 0
    onboarding_complete: bool = False

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
