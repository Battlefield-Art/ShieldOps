"""Change Risk Analyzer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AnalyzerStage(StrEnum):
    COLLECT_CHANGE = "collect_change"
    ANALYZE_DIFF = "analyze_diff"
    ASSESS_RISK = "assess_risk"
    PREDICT_BLAST_RADIUS = "predict_blast_radius"
    RECOMMEND = "recommend"
    REPORT = "report"


class ChangeType(StrEnum):
    DEPLOYMENT = "deployment"
    CONFIG_CHANGE = "config_change"
    INFRASTRUCTURE = "infrastructure"
    DATABASE_MIGRATION = "database_migration"
    FEATURE_FLAG = "feature_flag"
    ROLLBACK = "rollback"


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class ApprovalDecision(StrEnum):
    AUTO_APPROVE = "auto_approve"
    REQUIRE_REVIEW = "require_review"
    REQUIRE_SENIOR_REVIEW = "require_senior_review"
    BLOCK = "block"
    DEFER = "defer"


class ChangeRequest(BaseModel):
    """A change request submitted for risk analysis."""

    id: str = ""
    title: str = ""
    change_type: ChangeType = ChangeType.DEPLOYMENT
    author: str = ""
    repository: str = ""
    files_changed: int = 0
    lines_added: int = 0
    lines_removed: int = 0
    services_affected: list[str] = Field(default_factory=list)
    environment: str = "staging"
    scheduled_at: float = 0.0


class RiskAssessment(BaseModel):
    """Risk assessment result for a change request."""

    id: str = ""
    change_id: str = ""
    risk_level: RiskLevel = RiskLevel.MEDIUM
    risk_score: float = 0.0
    risk_factors: list[str] = Field(default_factory=list)
    historical_failure_rate: float = 0.0
    similar_changes_count: int = 0
    confidence: float = 0.0


class BlastRadiusPrediction(BaseModel):
    """Predicted blast radius for a change request."""

    id: str = ""
    change_id: str = ""
    affected_services: list[str] = Field(default_factory=list)
    affected_users_estimate: int = 0
    data_at_risk: list[str] = Field(default_factory=list)
    recovery_time_estimate_min: int = 0
    cascading_failures: list[str] = Field(default_factory=list)


class ChangeRecommendation(BaseModel):
    """Approval recommendation for a change request."""

    id: str = ""
    change_id: str = ""
    approval_decision: ApprovalDecision = ApprovalDecision.REQUIRE_REVIEW
    reasoning: str = ""
    required_reviewers: list[str] = Field(default_factory=list)
    rollback_plan: str = ""
    canary_suggested: bool = False
    monitoring_requirements: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ChangeRiskAnalyzerState(BaseModel):
    """Main state for the Change Risk Analyzer agent graph."""

    request_id: str = ""
    stage: AnalyzerStage = AnalyzerStage.COLLECT_CHANGE
    tenant_id: str = ""

    # Change data
    change_requests: list[ChangeRequest] = Field(default_factory=list)

    # Analysis results
    risk_assessments: list[dict[str, Any]] = Field(default_factory=list)
    blast_radius_predictions: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[dict[str, Any]] = Field(default_factory=list)

    # Metrics
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: int = 0
    session_start: float = 0.0
    session_duration_ms: float = 0.0

    # Error
    error: str = ""
