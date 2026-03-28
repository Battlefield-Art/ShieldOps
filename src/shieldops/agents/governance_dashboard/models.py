"""State models for the Governance Dashboard Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class GovernanceStage(StrEnum):
    """Stages in the governance dashboard workflow."""

    COLLECT_METRICS = "collect_metrics"
    ASSESS_POLICIES = "assess_policies"
    SCORE_RISK = "score_risk"
    GENERATE_INSIGHTS = "generate_insights"
    EXECUTIVE_SUMMARY = "executive_summary"
    REPORT = "report"


class PolicyDomain(StrEnum):
    """Domains for policy assessment."""

    ACCESS_CONTROL = "access_control"
    DATA_PROTECTION = "data_protection"
    INCIDENT_RESPONSE = "incident_response"
    CHANGE_MANAGEMENT = "change_management"
    VENDOR_RISK = "vendor_risk"
    BUSINESS_CONTINUITY = "business_continuity"


class RiskPosture(StrEnum):
    """Overall risk posture levels."""

    STRONG = "strong"
    ADEQUATE = "adequate"
    NEEDS_IMPROVEMENT = "needs_improvement"
    WEAK = "weak"
    CRITICAL = "critical"


class GovernanceMetric(BaseModel):
    """A single governance metric data point."""

    id: str = ""
    name: str = ""
    domain: PolicyDomain = PolicyDomain.ACCESS_CONTROL
    value: float = 0.0
    target: float = 100.0
    unit: str = "%"
    source: str = ""
    collected_at: float = 0.0


class PolicyAssessment(BaseModel):
    """Assessment of a policy domain."""

    id: str = ""
    domain: PolicyDomain = PolicyDomain.ACCESS_CONTROL
    adherence_pct: float = 0.0
    controls_total: int = 0
    controls_passing: int = 0
    gaps: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    assessed_at: float = 0.0


class RiskScore(BaseModel):
    """Risk score for a domain."""

    id: str = ""
    domain: PolicyDomain = PolicyDomain.ACCESS_CONTROL
    score: float = 0.0
    posture: RiskPosture = RiskPosture.ADEQUATE
    factors: list[str] = Field(default_factory=list)
    trend: str = "stable"
    scored_at: float = 0.0


class GovernanceDashboardState(BaseModel):
    """Full state for the Governance Dashboard workflow."""

    request_id: str = ""
    stage: GovernanceStage = GovernanceStage.COLLECT_METRICS
    tenant_id: str = ""

    # Collected metrics
    metrics: list[GovernanceMetric] = Field(default_factory=list)

    # Policy assessments
    policy_assessments: list[PolicyAssessment] = Field(
        default_factory=list,
    )

    # Risk scores
    risk_scores: list[RiskScore] = Field(default_factory=list)

    # Overall posture
    overall_posture: RiskPosture = RiskPosture.ADEQUATE

    # Insights and summary
    insights: list[str] = Field(default_factory=list)
    executive_summary: str = ""

    # Stats & reporting
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)

    # Workflow metadata
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: int = 0
    error: str = ""
