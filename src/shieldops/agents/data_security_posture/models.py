"""State models for the Data Security Posture Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ────────────────────────────────────────────────


class DSPStage(StrEnum):
    """Workflow stages for data security posture management."""

    DISCOVER_DATA_STORES = "discover_data_stores"
    CLASSIFY_DATA = "classify_data"
    ASSESS_RISKS = "assess_risks"
    APPLY_CONTROLS = "apply_controls"
    VALIDATE_POSTURE = "validate_posture"
    REPORT = "report"


class DataClassification(StrEnum):
    """Classification levels for discovered data."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PII = "pii"
    PHI = "phi"


class ProtectionLevel(StrEnum):
    """Protection levels applied to data stores."""

    NONE = "none"
    BASIC = "basic"
    STANDARD = "standard"
    ENHANCED = "enhanced"
    MAXIMUM = "maximum"


# ── Domain Models ───────────────────────────────────────────


class DataStore(BaseModel):
    """A discovered data store."""

    store_id: str = ""
    store_type: str = ""
    cloud_provider: str = ""
    region: str = ""
    name: str = ""
    size_gb: float = 0.0
    record_count: int = 0
    encryption_at_rest: bool = False
    encryption_in_transit: bool = False
    public_access: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class ClassificationResult(BaseModel):
    """Result of data classification for a store."""

    store_id: str = ""
    classification: str = DataClassification.INTERNAL
    pii_detected: bool = False
    phi_detected: bool = False
    sensitive_columns: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    sample_count: int = 0


class RiskAssessment(BaseModel):
    """Risk assessment for a classified data store."""

    store_id: str = ""
    risk_score: float = 0.0
    classification: str = DataClassification.INTERNAL
    exposure_type: str = ""
    compliance_gaps: list[str] = Field(default_factory=list)
    attack_vectors: list[str] = Field(default_factory=list)
    business_impact: str = "medium"


class ProtectionControl(BaseModel):
    """A protection control applied to a data store."""

    control_id: str = ""
    store_id: str = ""
    control_type: str = ""
    protection_level: str = ProtectionLevel.STANDARD
    status: str = "pending"
    applied_at: str = ""
    policy_reference: str = ""


class PostureValidation(BaseModel):
    """Validation result for applied controls."""

    store_id: str = ""
    control_id: str = ""
    validation_passed: bool = False
    compliance_status: str = ""
    gaps_remaining: list[str] = Field(default_factory=list)
    remediation_needed: bool = False


# ── Reasoning Step ──────────────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the DSP workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


# ── LangGraph State ─────────────────────────────────────────


class DataSecurityPostureState(BaseModel):
    """Full state for a data security posture workflow run."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: str = DSPStage.DISCOVER_DATA_STORES
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline outputs
    stores_discovered: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    controls_applied: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    validations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Aggregates
    total_stores: int = 0
    sensitive_store_count: int = 0
    high_risk_count: int = 0
    posture_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
