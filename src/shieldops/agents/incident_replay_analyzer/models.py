"""State models for the Incident Replay Analyzer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ------------------------------------------------


class IRAStage(StrEnum):
    """Workflow stages for incident replay."""

    SELECT_INCIDENTS = "select_incidents"
    RECONSTRUCT_TIMELINE = "reconstruct_timeline"
    ANALYZE_DECISIONS = "analyze_decisions"
    IDENTIFY_IMPROVEMENTS = "identify_improvements"
    GENERATE_PLAYBOOKS = "generate_playbooks"
    REPORT = "report"


class IncidentCategory(StrEnum):
    """Category of incident."""

    SECURITY_BREACH = "security_breach"
    SERVICE_OUTAGE = "service_outage"
    DATA_LEAK = "data_leak"
    COMPLIANCE_VIOLATION = "compliance_violation"
    INSIDER_THREAT = "insider_threat"


class LessonType(StrEnum):
    """Type of lesson learned."""

    DETECTION_GAP = "detection_gap"
    RESPONSE_DELAY = "response_delay"
    COMMUNICATION_FAILURE = "communication_failure"
    TOOLING_GAP = "tooling_gap"
    PROCESS_IMPROVEMENT = "process_improvement"


# -- Domain Models -------------------------------------------


class IncidentSelection(BaseModel):
    """A selected incident for replay."""

    incident_id: str = ""
    category: IncidentCategory = IncidentCategory.SECURITY_BREACH
    severity: str = "high"
    date: str = ""
    summary: str = ""


class TimelineEvent(BaseModel):
    """An event in the incident timeline."""

    event_id: str = ""
    incident_id: str = ""
    timestamp: str = ""
    action: str = ""
    actor: str = ""
    outcome: str = ""


class DecisionAnalysis(BaseModel):
    """Analysis of a decision made during incident."""

    decision_id: str = ""
    incident_id: str = ""
    decision: str = ""
    effectiveness: float = 0.0
    alternative: str = ""


class Improvement(BaseModel):
    """An identified improvement opportunity."""

    improvement_id: str = ""
    lesson_type: LessonType = LessonType.PROCESS_IMPROVEMENT
    description: str = ""
    priority: int = 0
    effort: str = "medium"


class PlaybookEntry(BaseModel):
    """A generated playbook entry."""

    playbook_id: str = ""
    category: IncidentCategory = IncidentCategory.SECURITY_BREACH
    title: str = ""
    steps: list[str] = Field(default_factory=list)
    source_incidents: list[str] = Field(default_factory=list)


# -- Reasoning + State ---------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class IncidentReplayAnalyzerState(BaseModel):
    """Full state for the Incident Replay Analyzer."""

    request_id: str = ""
    tenant_id: str = ""
    stage: IRAStage = IRAStage.SELECT_INCIDENTS
    config: dict[str, Any] = Field(default_factory=dict)

    selected_incidents: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    timeline_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    decision_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    improvements: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    playbooks: list[dict[str, Any]] = Field(
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
