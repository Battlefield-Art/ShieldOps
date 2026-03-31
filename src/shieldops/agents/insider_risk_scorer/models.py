"""Insider Risk Scorer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IRSStage(StrEnum):
    """Stages in the insider risk scoring lifecycle."""

    COLLECT_SIGNALS = "collect_signals"
    ANALYZE_BEHAVIOR = "analyze_behavior"
    SCORE_RISK = "score_risk"
    DETECT_ANOMALY = "detect_anomaly"
    ALERT = "alert"
    REPORT = "report"


class RiskTier(StrEnum):
    """Risk classification tiers for insider scoring."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"
    UNKNOWN = "unknown"


class BehaviorCategory(StrEnum):
    """Categories of insider behavior to analyze."""

    ACCESS_PATTERN = "access_pattern"
    DATA_MOVEMENT = "data_movement"
    PEER_DEVIATION = "peer_deviation"
    PRIVILEGE_USAGE = "privilege_usage"
    TEMPORAL_ANOMALY = "temporal_anomaly"
    COMMUNICATION_PATTERN = "communication_pattern"


class UserSignal(BaseModel):
    """Raw behavioral signal from an identity source."""

    signal_id: str = ""
    user_id: str = ""
    source: str = ""
    action: str = ""
    resource: str = ""
    timestamp: float = 0.0
    geo_location: str = ""
    risk_indicators: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BehaviorProfile(BaseModel):
    """Behavioral profile for a user against peer group."""

    user_id: str = ""
    department: str = ""
    peer_group: str = ""
    avg_daily_actions: float = 0.0
    typical_hours: str = ""
    typical_resources: list[str] = Field(default_factory=list)
    data_volume_baseline_mb: float = 0.0
    deviation_score: float = 0.0


class RiskScore(BaseModel):
    """Composite insider risk score for a user."""

    user_id: str = ""
    overall_score: float = 0.0
    tier: RiskTier = RiskTier.UNKNOWN
    category_scores: dict[str, float] = Field(default_factory=dict)
    contributing_factors: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    recommended_actions: list[str] = Field(default_factory=list)


class BehavioralAnomaly(BaseModel):
    """Detected behavioral anomaly for a user."""

    anomaly_id: str = ""
    user_id: str = ""
    category: BehaviorCategory = BehaviorCategory.ACCESS_PATTERN
    description: str = ""
    severity: float = 0.0
    baseline_value: str = ""
    observed_value: str = ""
    confidence: float = 0.0


class ReasoningStep(BaseModel):
    """Audit trail entry for the scoring workflow."""

    step_number: int = 0
    action: str = ""
    input_summary: str = ""
    output_summary: str = ""
    duration_ms: int = 0
    tool_used: str | None = None


class InsiderRiskScorerState(BaseModel):
    """Full state for an insider risk scoring run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: IRSStage = IRSStage.COLLECT_SIGNALS

    # Pipeline fields
    signals: list[dict[str, Any]] = Field(default_factory=list)
    behavior_profiles: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_scores: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    anomalies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    high_risk_users: list[str] = Field(default_factory=list)
    total_users_scored: int = 0
    anomaly_count: int = 0

    # Workflow tracking
    session_start: float = 0.0
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
