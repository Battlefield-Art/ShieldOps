"""State models for the Threat Simulation Engine Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class TSEStage(StrEnum):
    """Stages in the threat simulation lifecycle."""

    PLAN_SCENARIO = "plan_scenario"
    DEPLOY_ATTACK = "deploy_attack"
    MONITOR_DETECTION = "monitor_detection"
    EVALUATE_RESPONSE = "evaluate_response"
    GENERATE_GAPS = "generate_gaps"
    REPORT = "report"


class AttackComplexity(StrEnum):
    """Complexity level of simulated attack."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    ADVANCED = "advanced"


class SimulationType(StrEnum):
    """Type of adversary simulation campaign."""

    RED_TEAM = "red_team"
    PURPLE_TEAM = "purple_team"
    TABLETOP = "tabletop"
    AUTOMATED_BAS = "automated_bas"
    TTP_REPLAY = "ttp_replay"
    FULL_CHAIN = "full_chain"


# --- Domain models ---


class AttackScenario(BaseModel):
    """A planned adversary simulation scenario."""

    scenario_id: str = ""
    name: str = ""
    description: str = ""
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    complexity: AttackComplexity = AttackComplexity.MEDIUM
    simulation_type: SimulationType = SimulationType.PURPLE_TEAM
    target_assets: list[str] = Field(default_factory=list)
    expected_detections: list[str] = Field(default_factory=list)


class DeployedAttack(BaseModel):
    """A deployed attack execution result."""

    attack_id: str = ""
    scenario_id: str = ""
    technique_id: str = ""
    tactic: str = ""
    status: str = "pending"
    executed_at: datetime | None = None
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    success: bool = False


class DetectionResult(BaseModel):
    """Detection monitoring result for a deployed attack."""

    detection_id: str = ""
    attack_id: str = ""
    detected: bool = False
    detection_source: str = ""
    detection_time_ms: int = 0
    alert_id: str = ""
    rule_name: str = ""


class ResponseEvaluation(BaseModel):
    """Blue team response evaluation for a detection."""

    evaluation_id: str = ""
    detection_id: str = ""
    response_time_ms: int = 0
    response_actions: list[str] = Field(default_factory=list)
    containment_effective: bool = False
    score: float = 0.0


class DetectionGap(BaseModel):
    """A gap identified in detection coverage."""

    gap_id: str = ""
    mitre_technique: str = ""
    tactic: str = ""
    severity: str = "medium"
    description: str = ""
    recommendation: str = ""
    detection_exists: bool = False
    detection_effective: bool = False


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the simulation workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ThreatSimulationEngineState(BaseModel):
    """Full state for a threat simulation engine run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: TSEStage = TSEStage.PLAN_SCENARIO

    # Inputs
    campaign_name: str = ""
    simulation_type: SimulationType = SimulationType.PURPLE_TEAM
    target_techniques: list[str] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    scenarios: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    attacks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    detections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    evaluations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    gaps: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_attacks: int = 0
    detected_count: int = 0
    gap_count: int = 0
    detection_rate: float = 0.0
    overall_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
