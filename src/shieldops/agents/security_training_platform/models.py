"""State models for the Security Training Platform Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ----------------------------------------------------------


class STPStage(StrEnum):
    """Workflow stages for security training platform."""

    ASSESS_BASELINE = "assess_baseline"
    CREATE_CAMPAIGN = "create_campaign"
    DEPLOY_SIMULATION = "deploy_simulation"
    TRACK_RESULTS = "track_results"
    SCORE_RISK = "score_risk"
    REPORT = "report"


class CampaignType(StrEnum):
    """Types of security training campaigns."""

    PHISHING = "phishing"
    QUIZ = "quiz"
    COMPLIANCE = "compliance"
    SOCIAL_ENGINEERING = "social_engineering"
    PASSWORD_HYGIENE = "password_hygiene"
    INCIDENT_RESPONSE = "incident_response"
    CUSTOM = "custom"


class RiskTier(StrEnum):
    """Risk tier classification for users/teams."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


# -- Domain Models -----------------------------------------------------


class BaselineAssessment(BaseModel):
    """Baseline security awareness assessment for a team."""

    team_id: str = ""
    team_name: str = ""
    user_count: int = 0
    avg_awareness_score: float = 0.0
    phishing_click_rate: float = 0.0
    compliance_completion: float = 0.0
    last_training: datetime | None = None
    weaknesses: list[str] = Field(default_factory=list)


class TrainingCampaign(BaseModel):
    """A security training campaign configuration."""

    campaign_id: str = ""
    campaign_type: CampaignType = CampaignType.PHISHING
    target_teams: list[str] = Field(default_factory=list)
    target_user_count: int = 0
    difficulty: str = "medium"
    duration_days: int = 7
    description: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class SimulationResult(BaseModel):
    """Result of a deployed training simulation."""

    simulation_id: str = ""
    campaign_id: str = ""
    user_id: str = ""
    team_id: str = ""
    action_taken: str = ""
    time_to_action_ms: int = 0
    reported_suspicious: bool = False
    clicked_link: bool = False
    entered_credentials: bool = False
    score: float = 0.0


class UserRiskScore(BaseModel):
    """Risk score for an individual user or team."""

    entity_id: str = ""
    entity_type: str = "user"
    risk_tier: RiskTier = RiskTier.MEDIUM
    risk_score: float = 0.0
    click_rate: float = 0.0
    training_completion: float = 0.0
    improvement_trend: float = 0.0
    recommended_training: list[str] = Field(default_factory=list)


class CampaignSummary(BaseModel):
    """Summary of a completed training campaign."""

    campaign_id: str = ""
    total_targeted: int = 0
    total_completed: int = 0
    avg_score: float = 0.0
    click_rate: float = 0.0
    report_rate: float = 0.0
    improvement_pct: float = 0.0


# -- Reasoning + State -------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the training workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityTrainingPlatformState(BaseModel):
    """Full state for the Security Training Platform workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: STPStage = STPStage.ASSESS_BASELINE
    training_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Baseline
    baseline_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    avg_awareness: float = 0.0

    # Campaign
    campaigns: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_targeted_users: int = 0

    # Simulation
    simulation_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    overall_click_rate: float = 0.0

    # Tracking
    tracked_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    completion_rate: float = 0.0

    # Risk scores
    risk_scores: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    high_risk_count: int = 0

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
