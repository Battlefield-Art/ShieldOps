"""Security Scorecard Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ScorecardStage(StrEnum):
    """Stages of the security scorecard pipeline."""

    COLLECT_DOMAIN_SCORES = "collect_domain_scores"
    CALCULATE_COMPOSITE = "calculate_composite"
    TRACK_TRENDS = "track_trends"
    COMPARE_BENCHMARKS = "compare_benchmarks"
    GENERATE_INSIGHTS = "generate_insights"
    REPORT = "report"


class SecurityDomain(StrEnum):
    """Security domains for scoring."""

    ENDPOINT = "endpoint"
    NETWORK = "network"
    CLOUD = "cloud"
    IDENTITY = "identity"
    DATA = "data"
    APPLICATION = "application"
    COMPLIANCE = "compliance"
    OPERATIONS = "operations"


class ScoreGrade(StrEnum):
    """Letter grades for security scores."""

    A_PLUS = "a_plus"
    A = "a"
    B = "b"
    C = "c"
    D = "d"
    F = "f"


class DomainScore(BaseModel):
    """Score for a single security domain."""

    domain: SecurityDomain = SecurityDomain.ENDPOINT
    score: float = 0.0
    grade: ScoreGrade = ScoreGrade.C
    weight: float = 1.0
    findings_count: int = 0
    critical_issues: int = 0
    details: str = ""


class CompositeScore(BaseModel):
    """Weighted composite security score."""

    total_score: float = 0.0
    grade: ScoreGrade = ScoreGrade.C
    domain_scores: list[DomainScore] = Field(
        default_factory=list,
    )
    weakest_domain: str = ""
    strongest_domain: str = ""


class TrendData(BaseModel):
    """Trend data for score tracking."""

    period: str = ""
    score: float = 0.0
    delta: float = 0.0
    direction: str = ""
    events_count: int = 0


class BenchmarkComparison(BaseModel):
    """Comparison against industry benchmarks."""

    benchmark_name: str = ""
    industry_avg: float = 0.0
    our_score: float = 0.0
    percentile: float = 0.0
    gap: float = 0.0


class SecurityInsight(BaseModel):
    """LLM-generated security insight."""

    category: str = ""
    insight: str = ""
    severity: str = ""
    recommendation: str = ""
    effort: str = ""


class SecurityScorecardState(BaseModel):
    """Full state for a security scorecard run."""

    # Input
    tenant_id: str = ""
    request_id: str = ""

    # Pipeline data
    domain_scores: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    composite_score: dict[str, Any] = Field(
        default_factory=dict,
    )
    trends: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    benchmarks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    insights: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metrics
    overall_grade: str = ""
    improvement_areas: list[str] = Field(
        default_factory=list,
    )

    # Workflow tracking
    current_stage: str = ScorecardStage.COLLECT_DOMAIN_SCORES
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    error: str = ""
