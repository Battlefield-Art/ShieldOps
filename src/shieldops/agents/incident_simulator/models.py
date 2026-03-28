"""State models for Incident Simulator Agent."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class SimStage(StrEnum):
    """Stages in the simulation workflow."""

    DESIGN_SCENARIO = "design_scenario"
    INJECT_EVENTS = "inject_events"
    OBSERVE_RESPONSE = "observe_response"
    SCORE_PERFORMANCE = "score_performance"
    DEBRIEF = "debrief"
    REPORT = "report"


class ScenarioType(StrEnum):
    """Simulation scenario types."""

    RANSOMWARE = "ransomware"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN = "supply_chain"
    DDOS = "ddos"
    APT = "apt"


class ExerciseMode(StrEnum):
    """Exercise execution modes."""

    TABLETOP = "tabletop"
    FUNCTIONAL = "functional"
    FULL_SCALE = "full_scale"
    PURPLE_TEAM = "purple_team"
    RED_TEAM = "red_team"


class TeamScore(BaseModel):
    """Score for a participating team."""

    team_name: str = ""
    detection_score: float = 0.0
    response_score: float = 0.0
    communication_score: float = 0.0
    overall: float = 0.0


class ExerciseScope(StrEnum):
    """Exercise scope levels."""

    TABLETOP = "tabletop"
    FUNCTIONAL = "functional"
    FULL_SCALE = "full_scale"


class PerformanceMetric(StrEnum):
    """Performance measurement categories."""

    DETECTION_TIME = "detection_time"
    CONTAINMENT_TIME = "containment_time"
    COMMUNICATION_SPEED = "communication_speed"
    DECISION_QUALITY = "decision_quality"
    ESCALATION_ACCURACY = "escalation_accuracy"


class ExerciseDesign(BaseModel):
    """Designed exercise definition."""

    id: str = ""
    name: str = ""
    scope: ExerciseScope = ExerciseScope.TABLETOP
    scenario_type: str = ""
    objectives: list[str] = Field(default_factory=list)
    participants: list[str] = Field(default_factory=list)
    duration_min: int = 60
    injects_planned: int = 0
    success_criteria: dict[str, str] = Field(default_factory=dict)


class ScenarioInjection(BaseModel):
    """A single scenario inject event."""

    id: str = ""
    inject_number: int = 0
    title: str = ""
    description: str = ""
    injected_at: float = 0.0
    expected_response: str = ""
    severity: str = "medium"
    target_role: str = ""


class ResponseObservation(BaseModel):
    """Observation of team response to an inject."""

    id: str = ""
    inject_id: str = ""
    observer: str = ""
    response_time_sec: float = 0.0
    actions_taken: list[str] = Field(default_factory=list)
    communication_quality: str = "adequate"
    decision_quality: str = "adequate"
    notes: str = ""


class PerformanceMeasurement(BaseModel):
    """A single performance measurement."""

    id: str = ""
    metric: PerformanceMetric = PerformanceMetric.DETECTION_TIME
    value: float = 0.0
    unit: str = ""
    target: float = 0.0
    met_target: bool = False


class ReadinessScore(BaseModel):
    """Overall readiness assessment."""

    id: str = ""
    overall_score: float = 0.0
    grade: str = "F"
    category_scores: dict[str, float] = Field(default_factory=dict)
    strengths: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class IncidentSimulatorState(BaseModel):
    """Full state for Incident Simulator."""

    request_id: str = ""
    stage: SimStage = SimStage.DESIGN_SCENARIO
    tenant_id: str = ""
    scenario_type: ScenarioType = ScenarioType.RANSOMWARE
    exercise_mode: ExerciseMode = ExerciseMode.TABLETOP
    exercise: ExerciseDesign | None = None
    injects: list[ScenarioInjection] = Field(default_factory=list)
    observations: list[ResponseObservation] = Field(default_factory=list)
    measurements: list[PerformanceMeasurement] = Field(default_factory=list)
    readiness: ReadinessScore | None = None
    team_scores: list[TeamScore] = Field(default_factory=list)
    readiness_score: float = 0.0
    report_summary: str = ""
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    session_start: float = 0.0
    duration_ms: int = 0
