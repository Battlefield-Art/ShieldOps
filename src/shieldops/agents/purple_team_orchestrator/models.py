"""State models for Purple Team Orchestrator Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PurpleStage(StrEnum):
    """Stages of the purple team workflow."""

    PLAN_EXERCISE = "plan_exercise"
    EXECUTE_ATTACKS = "execute_attacks"
    MONITOR_DETECTIONS = "monitor_detections"
    ASSESS_RESPONSES = "assess_responses"
    SCORE_EXERCISE = "score_exercise"
    REPORT = "report"


class ExerciseType(StrEnum):
    """Types of purple team exercises."""

    TABLETOP = "tabletop"
    SIMULATION = "simulation"
    LIVE_FIRE = "live_fire"
    ASSUMED_BREACH = "assumed_breach"


class TeamScore(StrEnum):
    """Scoring tiers for team performance."""

    EXCELLENT = "excellent"
    GOOD = "good"
    ADEQUATE = "adequate"
    NEEDS_IMPROVEMENT = "needs_improvement"
    FAILED = "failed"


class ExercisePlan(BaseModel):
    """Plan for a purple team exercise."""

    id: str = ""
    name: str = ""
    exercise_type: ExerciseType = ExerciseType.SIMULATION
    objectives: list[str] = Field(default_factory=list)
    attack_scenarios: list[str] = Field(default_factory=list)
    expected_detections: list[str] = Field(default_factory=list)
    duration_minutes: int = 60
    participants: list[str] = Field(default_factory=list)


class AttackExecution(BaseModel):
    """Record of an attack executed during exercise."""

    id: str = ""
    scenario: str = ""
    technique_id: str = ""
    target: str = ""
    success: bool = False
    timestamp: float = 0.0
    evidence: list[str] = Field(default_factory=list)


class DetectionMonitor(BaseModel):
    """Detection observed by the blue team."""

    id: str = ""
    attack_id: str = ""
    detection_rule: str = ""
    detected: bool = False
    time_to_detect_sec: float = 0.0
    alert_fidelity: float = 0.0
    false_positive: bool = False


class ResponseAssessment(BaseModel):
    """Assessment of blue team response."""

    id: str = ""
    detection_id: str = ""
    response_action: str = ""
    time_to_respond_sec: float = 0.0
    containment_effective: bool = False
    evidence: list[str] = Field(default_factory=list)


class ExerciseScore(BaseModel):
    """Scoring for the exercise."""

    id: str = ""
    category: str = ""
    score: TeamScore = TeamScore.ADEQUATE
    points: float = 0.0
    max_points: float = 100.0
    details: str = ""


class PurpleTeamOrchestratorState(BaseModel):
    """Full state of a purple team exercise."""

    # Identity
    request_id: str = ""
    stage: PurpleStage = PurpleStage.PLAN_EXERCISE
    tenant_id: str = ""

    # Data
    plan: ExercisePlan = Field(default_factory=ExercisePlan)
    attacks_executed: list[AttackExecution] = Field(default_factory=list)
    detections_observed: list[DetectionMonitor] = Field(default_factory=list)
    responses_assessed: list[ResponseAssessment] = Field(default_factory=list)
    scores: list[ExerciseScore] = Field(default_factory=list)

    # Metrics
    red_team_score: float = 0.0
    blue_team_score: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Tracking
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
