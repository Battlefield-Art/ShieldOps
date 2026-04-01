"""State models for the Security Policy Optimizer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class SPOStage(StrEnum):
    """Workflow stages for security policy optimization."""

    COLLECT_POLICIES = "collect_policies"
    ANALYZE_EFFECTIVENESS = "analyze_effectiveness"
    IDENTIFY_OPTIMIZATIONS = "identify_optimizations"
    APPLY_CHANGES = "apply_changes"
    VALIDATE_CHANGES = "validate_changes"
    REPORT = "report"


class PolicyCategory(StrEnum):
    """Category of a security policy rule."""

    NETWORK = "network"
    IDENTITY = "identity"
    DATA = "data"
    APPLICATION = "application"
    ENDPOINT = "endpoint"
    CLOUD = "cloud"
    COMPLIANCE = "compliance"


class OptimizationAction(StrEnum):
    """Type of optimization action to apply."""

    TIGHTEN = "tighten"
    RELAX = "relax"
    MERGE = "merge"
    SPLIT = "split"
    DEPRECATE = "deprecate"
    RETUNE_THRESHOLD = "retune_threshold"
    ADD_EXCEPTION = "add_exception"


# ── Domain Models ─────────────────────────────────────


class PolicyRule(BaseModel):
    """A security policy rule under optimization."""

    rule_id: str = ""
    name: str = ""
    category: PolicyCategory = PolicyCategory.NETWORK
    source: str = ""
    enabled: bool = True
    severity: str = "medium"
    conditions: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyMetrics(BaseModel):
    """Effectiveness metrics for a policy rule."""

    rule_id: str = ""
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    trigger_count: int = 0
    precision: float = 0.0
    recall: float = 0.0
    avg_response_time_ms: int = 0
    last_triggered: str = ""


class OptimizationRecommendation(BaseModel):
    """A recommended optimization for a policy rule."""

    recommendation_id: str = ""
    rule_id: str = ""
    action: OptimizationAction = OptimizationAction.TIGHTEN
    reason: str = ""
    confidence: float = 0.0
    estimated_fp_reduction: float = 0.0
    risk_score: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class PolicyChange(BaseModel):
    """A change applied to a policy rule."""

    change_id: str = ""
    rule_id: str = ""
    action: OptimizationAction = OptimizationAction.TIGHTEN
    before: dict[str, Any] = Field(default_factory=dict)
    after: dict[str, Any] = Field(default_factory=dict)
    applied: bool = False
    rollback_available: bool = True


class ValidationResult(BaseModel):
    """Result from validating applied policy changes."""

    validation_id: str = ""
    change_id: str = ""
    passed: bool = False
    coverage_delta: float = 0.0
    fp_rate_delta: float = 0.0
    notes: str = ""


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the policy optimizer workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityPolicyOptimizerState(BaseModel):
    """Full state for the Security Policy Optimizer workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SPOStage = SPOStage.COLLECT_POLICIES
    config: dict[str, Any] = Field(default_factory=dict)

    policies: list[dict[str, Any]] = Field(default_factory=list)
    effectiveness: list[dict[str, Any]] = Field(default_factory=list)
    optimizations: list[dict[str, Any]] = Field(default_factory=list)
    changes: list[dict[str, Any]] = Field(default_factory=list)
    validations: list[dict[str, Any]] = Field(default_factory=list)

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
