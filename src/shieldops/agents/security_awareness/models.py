"""State models for Security Awareness Agent."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class AwarenessStage(StrEnum):
    """Stages in the security awareness workflow."""

    ASSESS_BASELINE = "assess_baseline"
    RUN_SIMULATIONS = "run_simulations"
    TRACK_TRAINING = "track_training"
    SCORE_RISK = "score_risk"
    RECOMMEND = "recommend"
    REPORT = "report"


class SimulationType(StrEnum):
    """Types of security awareness simulations."""

    PHISHING_EMAIL = "phishing_email"
    VISHING = "vishing"
    SMISHING = "smishing"
    USB_DROP = "usb_drop"
    SOCIAL_ENGINEERING = "social_engineering"
    PRETEXTING = "pretexting"


class RiskTier(StrEnum):
    """User/department risk tier classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class PhishingResult(BaseModel):
    """Result of a single phishing simulation for a user."""

    id: str = ""
    user_id: str = ""
    user_email: str = ""
    department: str = ""
    simulation_type: SimulationType = SimulationType.PHISHING_EMAIL
    sent_at: float = 0.0
    opened: bool = False
    clicked_link: bool = False
    submitted_credentials: bool = False
    reported_phish: bool = False
    response_time_sec: float = 0.0


class TrainingRecord(BaseModel):
    """Training completion record for a user."""

    id: str = ""
    user_id: str = ""
    user_email: str = ""
    department: str = ""
    course_name: str = ""
    assigned_at: float = 0.0
    completed_at: float = 0.0
    score_pct: float = 0.0
    passed: bool = False
    overdue: bool = False


class UserRiskScore(BaseModel):
    """Per-user risk score derived from simulations and training."""

    id: str = ""
    user_id: str = ""
    user_email: str = ""
    department: str = ""
    phishing_fail_rate: float = 0.0
    training_completion_pct: float = 0.0
    avg_training_score: float = 0.0
    risk_score: float = 0.0
    risk_tier: RiskTier = RiskTier.MEDIUM
    factors: list[str] = Field(default_factory=list)


class DepartmentSummary(BaseModel):
    """Aggregate risk summary for a department."""

    department: str = ""
    user_count: int = 0
    avg_risk_score: float = 0.0
    risk_tier: RiskTier = RiskTier.MEDIUM
    phishing_fail_rate: float = 0.0
    training_completion_pct: float = 0.0


class SecurityAwarenessState(BaseModel):
    """Full state for Security Awareness Agent."""

    request_id: str = ""
    stage: AwarenessStage = AwarenessStage.ASSESS_BASELINE
    tenant_id: str = ""
    simulation_type: SimulationType = SimulationType.PHISHING_EMAIL
    phishing_results: list[PhishingResult] = Field(
        default_factory=list,
    )
    training_records: list[TrainingRecord] = Field(
        default_factory=list,
    )
    risk_scores: list[UserRiskScore] = Field(
        default_factory=list,
    )
    department_summaries: list[DepartmentSummary] = Field(
        default_factory=list,
    )
    overall_score: float = 0.0
    recommendations: list[str] = Field(default_factory=list)
    report_summary: str = ""
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    session_start: float = 0.0
    duration_ms: int = 0
