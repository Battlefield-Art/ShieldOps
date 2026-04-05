"""State models for the Security Workflow Optimizer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class SWOStage(StrEnum):
    """Workflow stages for security workflow optimization."""

    COLLECT_WORKFLOWS = "collect_workflows"
    ANALYZE_PATTERNS = "analyze_patterns"
    IDENTIFY_BOTTLENECKS = "identify_bottlenecks"
    OPTIMIZE_PATHS = "optimize_paths"
    VALIDATE_IMPROVEMENTS = "validate_improvements"
    REPORT = "report"


class WorkflowCategory(StrEnum):
    """Category of security workflow."""

    INCIDENT_RESPONSE = "incident_response"
    THREAT_DETECTION = "threat_detection"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    ACCESS_REVIEW = "access_review"
    COMPLIANCE_CHECK = "compliance_check"


class OptimizationType(StrEnum):
    """Type of optimization applied."""

    PARALLELIZATION = "parallelization"
    ELIMINATION = "elimination"
    AUTOMATION = "automation"
    REORDERING = "reordering"
    CACHING = "caching"


# ── Domain Models ─────────────────────────────────────


class WorkflowRecord(BaseModel):
    """A collected security workflow."""

    workflow_id: str = ""
    name: str = ""
    category: WorkflowCategory = WorkflowCategory.INCIDENT_RESPONSE
    step_count: int = 0
    avg_duration_ms: int = 0
    execution_count: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class PatternAnalysis(BaseModel):
    """Analysis of workflow execution patterns."""

    pattern_id: str = ""
    workflow_id: str = ""
    frequency: int = 0
    avg_latency_ms: int = 0
    failure_rate: float = 0.0
    observations: list[str] = Field(default_factory=list)


class Bottleneck(BaseModel):
    """Identified bottleneck in a workflow."""

    bottleneck_id: str = ""
    workflow_id: str = ""
    step_name: str = ""
    impact_score: float = 0.0
    cause: str = ""
    suggestion: str = ""


class OptimizationResult(BaseModel):
    """Result from applying an optimization."""

    optimization_id: str = ""
    workflow_id: str = ""
    optimization_type: OptimizationType = OptimizationType.AUTOMATION
    before_ms: int = 0
    after_ms: int = 0
    improvement_pct: float = 0.0


class ValidationResult(BaseModel):
    """Validation of optimization improvements."""

    validation_id: str = ""
    optimizations_tested: int = 0
    passed: int = 0
    failed: int = 0
    rollback_needed: bool = False


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the workflow optimization."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityWorkflowOptimizerState(BaseModel):
    """Full state for the Security Workflow Optimizer workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SWOStage = SWOStage.COLLECT_WORKFLOWS
    config: dict[str, Any] = Field(default_factory=dict)

    workflows: list[dict[str, Any]] = Field(default_factory=list)
    patterns: list[dict[str, Any]] = Field(default_factory=list)
    bottlenecks: list[dict[str, Any]] = Field(default_factory=list)
    optimizations: list[dict[str, Any]] = Field(default_factory=list)
    validations: list[dict[str, Any]] = Field(default_factory=list)

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
