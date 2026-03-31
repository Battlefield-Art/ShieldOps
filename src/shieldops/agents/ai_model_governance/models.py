"""State models for the AI Model Governance Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class GovernanceStage(StrEnum):
    """Workflow stages for AI model governance."""

    INVENTORY_MODELS = "inventory_models"
    ASSESS_RISK = "assess_risk"
    CHECK_BIAS = "check_bias"
    VALIDATE_COMPLIANCE = "validate_compliance"
    ENFORCE_POLICY = "enforce_policy"
    REPORT = "report"


class RiskClassification(StrEnum):
    """EU AI Act risk classification tiers."""

    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"


class BiasCategory(StrEnum):
    """Categories of bias detected in AI models."""

    DEMOGRAPHIC = "demographic"
    SELECTION = "selection"
    MEASUREMENT = "measurement"
    REPRESENTATION = "representation"
    ALGORITHMIC = "algorithmic"
    LABEL = "label"


# ── Domain Models ─────────────────────────────────────


class ModelRecord(BaseModel):
    """A registered AI model in the governance inventory."""

    model_id: str = ""
    name: str = ""
    version: str = ""
    owner: str = ""
    framework: str = ""
    risk_tier: RiskClassification = RiskClassification.MINIMAL
    use_case: str = ""
    deployed: bool = False
    last_audit: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskAssessment(BaseModel):
    """Risk assessment for a governed AI model."""

    model_id: str = ""
    risk_tier: RiskClassification = RiskClassification.MINIMAL
    risk_score: float = 0.0
    impact_areas: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    reasoning: str = ""


class BiasReport(BaseModel):
    """Bias detection report for a model."""

    model_id: str = ""
    bias_categories: list[BiasCategory] = Field(default_factory=list)
    disparity_score: float = 0.0
    protected_groups_affected: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    passed: bool = True


class ComplianceResult(BaseModel):
    """Compliance validation result for a model."""

    model_id: str = ""
    framework: str = ""
    compliant: bool = True
    findings: list[str] = Field(default_factory=list)
    required_actions: list[str] = Field(default_factory=list)


class PolicyEnforcement(BaseModel):
    """Policy enforcement action for a model."""

    model_id: str = ""
    policy_id: str = ""
    action: str = ""
    enforced: bool = False
    reason: str = ""


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the governance workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class AIModelGovernanceState(BaseModel):
    """Full state for the AI Model Governance workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: GovernanceStage = GovernanceStage.INVENTORY_MODELS
    governance_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Inventory
    model_inventory: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_models: int = 0

    # Risk
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    high_risk_count: int = 0

    # Bias
    bias_reports: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    bias_detected_count: int = 0

    # Compliance
    compliance_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    non_compliant_count: int = 0

    # Policy
    policy_actions: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
