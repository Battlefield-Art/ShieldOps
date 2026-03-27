"""State models for the SOC Transformation Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TransformationStage(StrEnum):
    """Current stage in the transformation workflow."""

    ASSESS = "assess_current_soc"
    DESIGN = "design_target_architecture"
    PLAN = "plan_migration"
    EXECUTE = "execute_migration_steps"
    VALIDATE = "validate_transformation"
    REPORT = "report"


class SOCMaturity(StrEnum):
    """SOC maturity level (reactive -> autonomous)."""

    REACTIVE = "reactive"
    PROACTIVE = "proactive"
    ADAPTIVE = "adaptive"
    AUTONOMOUS = "autonomous"


class MigrationTarget(StrEnum):
    """Category of SOC asset being migrated."""

    SIEM_CONSOLIDATION = "siem_consolidation"
    DATA_PIPELINE = "data_pipeline"
    DETECTION_RULES = "detection_rules"
    WORKFLOW_AUTOMATION = "workflow_automation"
    RESPONSE_PLAYBOOKS = "response_playbooks"


# ── Domain Models ─────────────────────────────────────────


class SOCAssessment(BaseModel):
    """Assessment of the current SOC posture."""

    maturity: SOCMaturity = SOCMaturity.REACTIVE
    siem_vendors: list[str] = Field(default_factory=list)
    detection_rule_count: int = 0
    data_source_count: int = 0
    daily_event_volume_gb: float = 0.0
    mean_time_to_detect_min: float = 0.0
    mean_time_to_respond_min: float = 0.0
    automation_percentage: float = 0.0
    pain_points: list[str] = Field(default_factory=list)
    strengths: list[str] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)
    annual_siem_cost_usd: float = 0.0
    analyst_count: int = 0
    score: float = 0.0


class TargetArchitecture(BaseModel):
    """Designed target SOC architecture."""

    target_maturity: SOCMaturity = SOCMaturity.ADAPTIVE
    primary_siem: str = ""
    secondary_tools: list[str] = Field(default_factory=list)
    data_pipeline_design: str = ""
    detection_strategy: str = ""
    automation_targets: list[str] = Field(default_factory=list)
    estimated_cost_reduction_pct: float = 0.0
    estimated_mttd_improvement_pct: float = 0.0
    estimated_mttr_improvement_pct: float = 0.0
    architecture_diagram: str = ""
    rationale: str = ""


class MigrationStep(BaseModel):
    """A single step in the migration plan."""

    step_id: str = ""
    order: int = 0
    target: MigrationTarget = MigrationTarget.SIEM_CONSOLIDATION
    title: str = ""
    description: str = ""
    estimated_hours: float = 0.0
    risk_level: str = "medium"
    rollback_plan: str = ""
    dependencies: list[str] = Field(default_factory=list)
    status: str = "pending"
    result: dict[str, Any] = Field(default_factory=dict)


class MigrationPlan(BaseModel):
    """Full migration plan with ordered steps."""

    plan_id: str = ""
    steps: list[MigrationStep] = Field(default_factory=list)
    total_estimated_hours: float = 0.0
    phases: int = 0
    risk_summary: str = ""
    prerequisites: list[str] = Field(default_factory=list)


class ValidationResult(BaseModel):
    """Post-migration validation outcome."""

    check_name: str = ""
    passed: bool = False
    details: str = ""
    metric_before: float = 0.0
    metric_after: float = 0.0
    improvement_pct: float = 0.0


class ReasoningStep(BaseModel):
    """Audit trail entry for the transformation workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


# ── Workflow State ────────────────────────────────────────


class SOCTransformationState(BaseModel):
    """Full state for a SOC Transformation workflow run."""

    # Input
    tenant_id: str = ""
    transformation_scope: list[MigrationTarget] = Field(
        default_factory=list,
    )
    config: dict[str, Any] = Field(default_factory=dict)

    # Assessment
    assessment: SOCAssessment | None = None
    current_maturity: SOCMaturity = SOCMaturity.REACTIVE
    target_maturity: SOCMaturity = SOCMaturity.ADAPTIVE

    # Architecture
    target_architecture: TargetArchitecture | None = None

    # Migration
    migration_plan: MigrationPlan | None = None
    migration_steps: list[MigrationStep] = Field(
        default_factory=list,
    )
    steps_completed: int = 0

    # Execution tracking
    detection_rules_migrated: int = 0
    data_sources_connected: int = 0
    playbooks_deployed: int = 0
    workflows_automated: int = 0

    # Validation
    validation_results: list[ValidationResult] = Field(
        default_factory=list,
    )
    validation_passed: bool = False

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_stage: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
