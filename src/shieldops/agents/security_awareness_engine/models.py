"""Security Awareness Engine Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SAEStage(StrEnum):
    ASSESS_BASELINE = "assess_baseline"
    ANALYZE_PHISHING = "analyze_phishing"
    EVALUATE_TRAINING = "evaluate_training"
    IDENTIFY_RISKS = "identify_risks"
    GENERATE_PLAN = "generate_plan"
    REPORT = "report"


class RiskTier(StrEnum):
    CRITICAL_RISK = "critical_risk"
    HIGH_RISK = "high_risk"
    MODERATE_RISK = "moderate_risk"
    LOW_RISK = "low_risk"
    MINIMAL_RISK = "minimal_risk"


class TrainingModule(StrEnum):
    PHISHING = "phishing"
    SOCIAL_ENGINEERING = "social_engineering"
    PASSWORD_HYGIENE = "password_hygiene"
    DATA_HANDLING = "data_handling"
    INCIDENT_REPORTING = "incident_reporting"
    COMPLIANCE = "compliance"


class AwarenessBaseline(BaseModel):
    """Baseline awareness metrics for a department or org."""

    department: str = ""
    total_users: int = 0
    users_trained: int = 0
    avg_score: float = 0.0
    completion_rate: float = 0.0
    last_assessed: datetime | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class PhishingResult(BaseModel):
    """Result from a phishing simulation campaign."""

    campaign_id: str = ""
    campaign_name: str = ""
    department: str = ""
    emails_sent: int = 0
    emails_opened: int = 0
    links_clicked: int = 0
    credentials_submitted: int = 0
    reported_count: int = 0
    click_rate: float = 0.0
    report_rate: float = 0.0
    run_date: datetime | None = None


class TrainingCompletion(BaseModel):
    """Training module completion record."""

    user_id: str = ""
    department: str = ""
    module: TrainingModule = TrainingModule.PHISHING
    completed: bool = False
    score: float = 0.0
    attempts: int = 0
    completed_at: datetime | None = None
    overdue: bool = False


class UserRiskProfile(BaseModel):
    """Risk profile for a user based on awareness data."""

    user_id: str = ""
    department: str = ""
    risk_tier: RiskTier = RiskTier.MODERATE_RISK
    phishing_click_count: int = 0
    training_completion_pct: float = 0.0
    last_incident: datetime | None = None
    risk_factors: list[str] = Field(default_factory=list)
    recommended_modules: list[str] = Field(default_factory=list)


class TrainingPlan(BaseModel):
    """Generated training plan for a department or user group."""

    plan_id: str = ""
    target: str = ""
    priority: RiskTier = RiskTier.MODERATE_RISK
    modules: list[str] = Field(default_factory=list)
    frequency: str = ""
    rationale: str = ""
    estimated_impact: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int = 0
    action: str = ""
    input_summary: str = ""
    output_summary: str = ""
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityAwarenessEngineState(BaseModel):
    """Main state for the Security Awareness Engine graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SAEStage = SAEStage.ASSESS_BASELINE
    # Pipeline data
    baselines: list[dict[str, Any]] = Field(default_factory=list)
    phishing_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    training_completions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_profiles: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    training_plans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    # Aggregates
    total_users: int = 0
    overall_completion_rate: float = 0.0
    avg_phishing_click_rate: float = 0.0
    high_risk_user_count: int = 0
    summary: str = ""
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
