"""State models for the Situation Manager Agent."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SituationStage(StrEnum):
    """Stages of the situation management pipeline."""

    AGGREGATE_ALERTS = "aggregate_alerts"
    COMPOSE_NARRATIVE = "compose_narrative"
    PRIORITIZE_SITUATIONS = "prioritize_situations"
    RECOMMEND_ACTIONS = "recommend_actions"
    TRACK_OUTCOMES = "track_outcomes"
    REPORT = "report"


class SituationPriority(StrEnum):
    """Priority levels for situations."""

    P0_ACTIVE_ATTACK = "p0_active_attack"
    P1_HIGH_RISK = "p1_high_risk"
    P2_INVESTIGATION = "p2_investigation"
    P3_MONITORING = "p3_monitoring"
    P4_INFORMATIONAL = "p4_informational"


class OutcomeStatus(StrEnum):
    """Outcome status for tracked situations."""

    RESOLVED_AUTO = "resolved_auto"
    RESOLVED_ANALYST = "resolved_analyst"
    ESCALATED = "escalated"
    FALSE_POSITIVE = "false_positive"
    ONGOING = "ongoing"


class AlertAggregate(BaseModel):
    """Group of related alerts aggregated together."""

    id: str = ""
    alert_ids: list[str] = Field(default_factory=list)
    source_vendors: list[str] = Field(default_factory=list)
    common_entities: list[str] = Field(default_factory=list)
    severity: str = ""
    alert_count: int = 0
    time_span_seconds: float = 0.0
    raw_data: dict[str, Any] = Field(default_factory=dict)


class SituationNarrative(BaseModel):
    """Human-readable narrative for a situation."""

    id: str = ""
    aggregate_id: str = ""
    title: str = ""
    summary: str = ""
    attack_story: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    timeline: list[str] = Field(default_factory=list)


class PrioritizedSituation(BaseModel):
    """A situation with assigned priority."""

    id: str = ""
    narrative_id: str = ""
    priority: SituationPriority = SituationPriority.P3_MONITORING
    title: str = ""
    severity: str = ""
    confidence: float = 0.0
    auto_actionable: bool = False
    estimated_impact: str = ""
    vendor_count: int = 0
    alert_count: int = 0


class ActionRecommendation(BaseModel):
    """Recommended action for a situation."""

    id: str = ""
    situation_id: str = ""
    action_type: str = ""
    description: str = ""
    urgency: str = ""
    automated: bool = False
    playbook_ref: str = ""
    estimated_time_minutes: int = 0


class OutcomeTracking(BaseModel):
    """Tracking record for situation outcomes."""

    id: str = ""
    situation_id: str = ""
    status: OutcomeStatus = OutcomeStatus.ONGOING
    resolved_by: str = ""
    resolution_time_minutes: int = 0
    lessons_learned: str = ""
    false_positive_reason: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the workflow."""

    step_number: int = 0
    action: str = ""
    input_summary: str = ""
    output_summary: str = ""
    duration_ms: int = 0
    tool_used: str | None = None


class SituationManagerState(BaseModel):
    """Full state for a situation management run."""

    # Input
    tenant_id: str = ""
    time_window_minutes: int = 60

    # Pipeline data
    aggregates: list[AlertAggregate] = Field(default_factory=list)
    narratives: list[SituationNarrative] = Field(default_factory=list)
    situations: list[PrioritizedSituation] = Field(default_factory=list)
    recommendations: list[ActionRecommendation] = Field(default_factory=list)
    outcomes: list[OutcomeTracking] = Field(default_factory=list)

    # Metrics
    total_alerts_processed: int = 0
    total_situations: int = 0
    auto_resolved_count: int = 0

    # Workflow tracking
    current_stage: SituationStage = SituationStage.AGGREGATE_ALERTS
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
    session_duration_ms: int = 0
