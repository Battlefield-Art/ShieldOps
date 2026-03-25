"""State models for the Attack Campaign Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CampaignStage(StrEnum):
    """Stages of an attack campaign lifecycle."""

    PLAN = "plan"
    SELECT_TTPS = "select_ttps"
    EXECUTE = "execute"
    COLLECT_RESULTS = "collect_results"
    ASSESS_DEFENSES = "assess_defenses"
    REPORT = "report"


class AttackPhase(StrEnum):
    """MITRE ATT&CK kill chain phases."""

    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class SimulationMode(StrEnum):
    """Controls how aggressively simulation steps execute."""

    DRY_RUN = "dry_run"
    READ_ONLY = "read_only"
    CONTROLLED = "controlled"
    FULL = "full"


class TTPSelection(BaseModel):
    """A selected MITRE ATT&CK technique for the campaign."""

    id: str = ""
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    description: str = ""
    severity: str = "medium"
    platform: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)


class SimulationStep(BaseModel):
    """Result of executing a single simulation step."""

    id: str = ""
    campaign_id: str = ""
    ttp_id: str = ""
    phase: str = ""
    action: str = ""
    target: str = ""
    result: str = ""
    success: bool = False
    blocked_by: str = ""
    duration_ms: int = 0
    timestamp: datetime | None = None


class DefenseAssessment(BaseModel):
    """Assessment of defense coverage for a specific TTP."""

    id: str = ""
    ttp_id: str = ""
    detection_coverage: float = 0.0
    prevention_coverage: float = 0.0
    response_time_ms: int = 0
    gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class CampaignResult(BaseModel):
    """Aggregate result of an entire attack campaign."""

    id: str = ""
    campaign_name: str = ""
    total_steps: int = 0
    steps_blocked: int = 0
    steps_succeeded: int = 0
    detection_rate: float = 0.0
    prevention_rate: float = 0.0
    mean_detection_time_ms: float = 0.0
    mitre_coverage: dict[str, Any] = Field(default_factory=dict)


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class AttackCampaignState(BaseModel):
    """Full state of an attack campaign workflow."""

    # Identity
    request_id: str = ""
    stage: CampaignStage = CampaignStage.PLAN
    campaign_id: str = ""
    campaign_name: str = ""

    # Configuration
    target_scope: dict[str, Any] = Field(default_factory=dict)
    simulation_mode: SimulationMode = SimulationMode.DRY_RUN

    # Execution data
    ttp_selections: list[TTPSelection] = Field(default_factory=list)
    simulation_steps: list[SimulationStep] = Field(default_factory=list)
    defense_assessments: list[DefenseAssessment] = Field(default_factory=list)
    campaign_result: CampaignResult | None = None

    # Tracking
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str | None = None
