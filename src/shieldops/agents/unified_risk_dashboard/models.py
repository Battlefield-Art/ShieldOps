"""State models for the Unified Risk Dashboard Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class URDStage(StrEnum):
    """Stages of the unified risk dashboard lifecycle."""

    COLLECT_RISK_SIGNALS = "collect_risk_signals"
    NORMALIZE_SCORES = "normalize_scores"
    AGGREGATE_RISKS = "aggregate_risks"
    CALCULATE_POSTURE = "calculate_posture"
    PRIORITIZE_ACTIONS = "prioritize_actions"
    REPORT = "report"


class RiskDomain(StrEnum):
    """Domains of risk being tracked."""

    IDENTITY = "identity"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    CLOUD = "cloud"
    DATA = "data"
    APPLICATION = "application"
    COMPLIANCE = "compliance"
    SUPPLY_CHAIN = "supply_chain"


class PostureLevel(StrEnum):
    """Security posture levels."""

    CRITICAL = "critical"
    AT_RISK = "at_risk"
    NEEDS_ATTENTION = "needs_attention"
    ACCEPTABLE = "acceptable"
    STRONG = "strong"
    OPTIMAL = "optimal"


class RiskSignal(BaseModel):
    """A risk signal from a security agent or source."""

    signal_id: str = ""
    source_agent: str = ""
    domain: RiskDomain = RiskDomain.NETWORK
    severity: str = "medium"
    raw_score: float = Field(default=0.0, ge=0.0, le=1.0)
    title: str = ""
    description: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    timestamp: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class NormalizedScore(BaseModel):
    """A normalized risk score for cross-domain comparison."""

    score_id: str = ""
    signal_id: str = ""
    domain: RiskDomain = RiskDomain.NETWORK
    normalized_score: float = Field(default=0.0, ge=0.0, le=1.0)
    weight: float = Field(default=1.0, ge=0.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    normalization_method: str = ""


class AggregatedRisk(BaseModel):
    """Aggregated risk for a domain or category."""

    aggregation_id: str = ""
    domain: RiskDomain = RiskDomain.NETWORK
    aggregate_score: float = Field(default=0.0, ge=0.0, le=1.0)
    signal_count: int = 0
    critical_signals: int = 0
    trend: str = "stable"
    top_contributors: list[str] = Field(default_factory=list)


class PostureAssessment(BaseModel):
    """Overall security posture assessment."""

    assessment_id: str = ""
    overall_score: float = Field(default=0.0, ge=0.0, le=1.0)
    posture_level: PostureLevel = PostureLevel.ACCEPTABLE
    domain_scores: dict[str, float] = Field(default_factory=dict)
    strengths: list[str] = Field(default_factory=list)
    weaknesses: list[str] = Field(default_factory=list)
    trend: str = "stable"


class PrioritizedAction(BaseModel):
    """A prioritized remediation action."""

    action_id: str = ""
    priority: int = 0
    domain: RiskDomain = RiskDomain.NETWORK
    title: str = ""
    description: str = ""
    risk_reduction: float = Field(default=0.0, ge=0.0, le=1.0)
    effort: str = "medium"
    affected_assets: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class UnifiedRiskDashboardState(BaseModel):
    """Full LangGraph state for the Unified Risk Dashboard."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: URDStage = URDStage.COLLECT_RISK_SIGNALS
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    risk_signals: list[dict[str, Any]] = Field(default_factory=list)
    normalized_scores: list[dict[str, Any]] = Field(default_factory=list)
    aggregated_risks: list[dict[str, Any]] = Field(default_factory=list)
    posture: list[dict[str, Any]] = Field(default_factory=list)
    prioritized_actions: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)

    # Metrics
    signal_count: int = 0
    domain_count: int = 0
    action_count: int = 0

    # Metadata
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
