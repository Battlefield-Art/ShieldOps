"""Security Ops Dashboard Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SODStage(StrEnum):
    COLLECT_METRICS = "collect_metrics"
    CALCULATE_KPIS = "calculate_kpis"
    DETECT_ANOMALIES = "detect_anomalies"
    GENERATE_INSIGHTS = "generate_insights"
    BUILD_VIEWS = "build_views"
    REPORT = "report"


class MetricCategory(StrEnum):
    DETECTION = "detection"
    RESPONSE = "response"
    PREVENTION = "prevention"
    COMPLIANCE = "compliance"
    TEAM = "team"
    COST = "cost"


class AnomalyType(StrEnum):
    SPIKE = "spike"
    DROP = "drop"
    TREND_SHIFT = "trend_shift"
    SEASONAL = "seasonal"
    OUTLIER = "outlier"
    BASELINE_DRIFT = "baseline_drift"


class SecurityMetric(BaseModel):
    """A raw security operations metric."""

    id: str = ""
    name: str = ""
    category: MetricCategory = MetricCategory.DETECTION
    value: float = 0.0
    unit: str = ""
    timestamp: str = ""
    source: str = ""
    tags: list[str] = Field(default_factory=list)


class KPIResult(BaseModel):
    """A calculated KPI from raw metrics."""

    id: str = ""
    kpi_name: str = ""
    value: float = 0.0
    target: float = 0.0
    trend: str = ""
    period: str = ""
    meets_target: bool = False
    delta_pct: float = 0.0


class MetricAnomaly(BaseModel):
    """An anomaly detected in metric data."""

    id: str = ""
    metric_name: str = ""
    anomaly_type: AnomalyType = AnomalyType.SPIKE
    severity: str = "medium"
    expected_value: float = 0.0
    actual_value: float = 0.0
    deviation_pct: float = 0.0
    detected_at: str = ""


class DashboardInsight(BaseModel):
    """An actionable insight generated from KPIs."""

    id: str = ""
    title: str = ""
    description: str = ""
    priority: str = "medium"
    affected_kpis: list[str] = Field(default_factory=list)
    recommendation: str = ""
    impact_score: float = 0.0


class DashboardView(BaseModel):
    """A configured dashboard view/panel."""

    id: str = ""
    view_name: str = ""
    view_type: str = ""
    metrics_included: list[str] = Field(default_factory=list)
    time_range: str = "7d"
    refresh_interval_sec: int = 60
    audience: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityOpsDashboardState(BaseModel):
    """Main state for the Security Ops Dashboard agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SODStage = SODStage.COLLECT_METRICS

    metrics: list[SecurityMetric] = Field(
        default_factory=list,
    )
    kpi_results: list[KPIResult] = Field(
        default_factory=list,
    )
    anomalies: list[MetricAnomaly] = Field(
        default_factory=list,
    )
    insights: list[DashboardInsight] = Field(
        default_factory=list,
    )
    dashboard_views: list[DashboardView] = Field(
        default_factory=list,
    )

    report: str = ""
    total_metrics_collected: int = 0
    kpis_calculated: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
