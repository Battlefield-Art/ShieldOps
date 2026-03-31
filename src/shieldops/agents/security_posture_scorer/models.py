"""Security Posture Scorer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SPSStage(StrEnum):
    COLLECT_SIGNALS = "collect_signals"
    WEIGHT_CATEGORIES = "weight_categories"
    CALCULATE_SCORES = "calculate_scores"
    BENCHMARK = "benchmark"
    TREND_ANALYSIS = "trend_analysis"
    REPORT = "report"


class SignalSource(StrEnum):
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    IDENTITY_PROVIDER = "identity_provider"
    CLOUD_POSTURE = "cloud_posture"
    ENDPOINT_PROTECTION = "endpoint_protection"
    NETWORK_SECURITY = "network_security"
    DATA_PROTECTION = "data_protection"


class ScoreTier(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    CRITICAL = "critical"


class SecuritySignal(BaseModel):
    """A security signal from a source."""

    id: str = ""
    source: SignalSource = SignalSource.VULNERABILITY_SCANNER
    category: str = ""
    metric_name: str = ""
    value: float = 0.0
    max_value: float = 100.0
    timestamp: str = ""
    weight: float = 1.0
    tags: list[str] = Field(default_factory=list)


class CategoryWeight(BaseModel):
    """Weight configuration for a scoring category."""

    id: str = ""
    category: str = ""
    weight: float = 0.0
    cis_benchmark_id: str = ""
    description: str = ""
    signal_count: int = 0


class PostureScore(BaseModel):
    """A calculated posture score for a category."""

    id: str = ""
    category: str = ""
    score: float = 0.0
    max_score: float = 100.0
    tier: ScoreTier = ScoreTier.FAIR
    contributing_signals: int = 0
    findings: list[str] = Field(default_factory=list)


class BenchmarkComparison(BaseModel):
    """Comparison against industry benchmarks."""

    id: str = ""
    category: str = ""
    org_score: float = 0.0
    industry_avg: float = 0.0
    industry_top_10: float = 0.0
    percentile: int = 0
    framework: str = "CIS"


class TrendPoint(BaseModel):
    """A trend data point for posture scoring."""

    id: str = ""
    period: str = ""
    overall_score: float = 0.0
    delta: float = 0.0
    direction: str = "stable"
    forecast_30d: float = 0.0


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityPostureScorerState(BaseModel):
    """Main state for the Security Posture Scorer agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SPSStage = SPSStage.COLLECT_SIGNALS

    signals: list[SecuritySignal] = Field(default_factory=list)
    category_weights: list[CategoryWeight] = Field(default_factory=list)
    scores: list[PostureScore] = Field(default_factory=list)
    benchmarks: list[BenchmarkComparison] = Field(default_factory=list)
    trends: list[TrendPoint] = Field(default_factory=list)

    report: str = ""
    overall_score: float = 0.0
    overall_tier: str = ""

    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
