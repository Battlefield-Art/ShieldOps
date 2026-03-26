"""State models for the Reflection Engine Agent LangGraph workflow."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ReflectionStage(StrEnum):
    """Stages of the reflection pipeline."""

    COLLECT_ACTIONS = "collect_actions"
    EVALUATE_OUTCOMES = "evaluate_outcomes"
    IDENTIFY_MISTAKES = "identify_mistakes"
    GENERATE_IMPROVEMENTS = "generate_improvements"
    APPLY_LEARNINGS = "apply_learnings"
    REPORT = "report"


class OutcomeAssessment(StrEnum):
    """Assessment of an agent action's outcome."""

    EFFECTIVE = "effective"
    PARTIALLY_EFFECTIVE = "partially_effective"
    INEFFECTIVE = "ineffective"
    COUNTERPRODUCTIVE = "counterproductive"
    UNKNOWN = "unknown"


class ImprovementType(StrEnum):
    """Types of improvement recommendations."""

    DETECTION_RULE_TUNE = "detection_rule_tune"
    THRESHOLD_ADJUST = "threshold_adjust"
    PLAYBOOK_UPDATE = "playbook_update"
    FALSE_POSITIVE_SUPPRESS = "false_positive_suppress"
    ESCALATION_CHANGE = "escalation_change"


class AgentAction(BaseModel):
    """A recorded action taken by an agent."""

    id: str = ""
    agent_id: str = ""
    agent_type: str = ""
    action_type: str = ""
    description: str = ""
    timestamp: float = 0.0
    confidence: float = 0.0
    target_entity: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    actual_result: str = ""
    expected_result: str = ""
    duration_ms: int = 0


class OutcomeEvaluation(BaseModel):
    """Evaluation of an agent action's outcome."""

    action_id: str = ""
    assessment: OutcomeAssessment = OutcomeAssessment.UNKNOWN
    effectiveness_score: float = 0.0
    time_to_resolution_ms: int = 0
    false_positive: bool = False
    collateral_impact: str = ""
    counterfactual: str = ""
    reasoning: str = ""


class MistakeIdentification(BaseModel):
    """A pattern of mistakes identified across evaluations."""

    id: str = ""
    pattern_name: str = ""
    affected_agent_ids: list[str] = Field(default_factory=list)
    action_ids: list[str] = Field(default_factory=list)
    frequency: int = 0
    severity: str = ""
    root_cause: str = ""
    description: str = ""


class ImprovementRecommendation(BaseModel):
    """An actionable improvement recommendation."""

    id: str = ""
    mistake_id: str = ""
    improvement_type: ImprovementType = ImprovementType.THRESHOLD_ADJUST
    title: str = ""
    description: str = ""
    current_value: str = ""
    recommended_value: str = ""
    estimated_impact: str = ""
    auto_applicable: bool = False
    priority: int = 3


class LearningApplication(BaseModel):
    """Record of an improvement being applied."""

    improvement_id: str = ""
    applied: bool = False
    applied_to_agent: str = ""
    change_description: str = ""
    rollback_info: str = ""
    validation_result: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the reflection workflow."""

    step_number: int = 0
    action: str = ""
    input_summary: str = ""
    output_summary: str = ""
    duration_ms: int = 0
    tool_used: str | None = None


class ReflectionEngineState(BaseModel):
    """Full state for a reflection engine workflow run."""

    # Input
    agent_id: str = ""
    time_range_hours: int = 24
    tenant_id: str = ""

    # Pipeline data
    actions_reviewed: list[AgentAction] = Field(default_factory=list)
    evaluations: list[OutcomeEvaluation] = Field(default_factory=list)
    mistakes_found: list[MistakeIdentification] = Field(default_factory=list)
    improvements_recommended: list[ImprovementRecommendation] = Field(default_factory=list)
    learnings_applied: list[LearningApplication] = Field(default_factory=list)

    # Metrics
    effectiveness_score: float = 0.0
    total_actions_reviewed: int = 0
    total_mistakes_found: int = 0
    total_improvements: int = 0
    total_learnings_applied: int = 0
    false_positive_rate: float = 0.0

    # Workflow tracking
    current_stage: ReflectionStage = ReflectionStage.COLLECT_ACTIONS
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
    session_duration_ms: int = 0
