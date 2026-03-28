"""State models for the Security Dashboard Aggregator Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AggregatorStage(StrEnum):
    """Stages of the dashboard aggregator workflow."""

    COLLECT_AGENT_METRICS = "collect_agent_metrics"
    AGGREGATE_BY_DOMAIN = "aggregate_by_domain"
    CALCULATE_KPIS = "calculate_kpis"
    DETECT_ANOMALIES = "detect_anomalies"
    GENERATE_DASHBOARD = "generate_dashboard"
    REPORT = "report"


class MetricDomain(StrEnum):
    """Security metric domains."""

    DETECTION = "detection"
    PREVENTION = "prevention"
    RESPONSE = "response"
    COMPLIANCE = "compliance"
    COVERAGE = "coverage"
    OPERATIONS = "operations"


class KPIStatus(StrEnum):
    """Status of a KPI against its target."""

    ON_TARGET = "on_target"
    AT_RISK = "at_risk"
    OFF_TARGET = "off_target"


class AgentMetric(BaseModel):
    """A metric reported by a single agent."""

    agent_name: str = ""
    metric_name: str = ""
    value: float = 0.0
    unit: str = ""
    domain: MetricDomain = MetricDomain.DETECTION
    timestamp: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class DomainAggregate(BaseModel):
    """Aggregated metrics for a security domain."""

    domain: MetricDomain = MetricDomain.DETECTION
    metric_count: int = 0
    agents_reporting: int = 0
    avg_value: float = 0.0
    min_value: float = 0.0
    max_value: float = 0.0
    trend: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class KPICalculation(BaseModel):
    """A calculated KPI with target comparison."""

    name: str = ""
    value: float = 0.0
    target: float = 0.0
    unit: str = ""
    status: KPIStatus = KPIStatus.ON_TARGET
    trend_pct: float = 0.0
    domain: MetricDomain = MetricDomain.DETECTION


class MetricAnomaly(BaseModel):
    """An anomaly detected in agent metrics."""

    agent_name: str = ""
    metric_name: str = ""
    expected_value: float = 0.0
    actual_value: float = 0.0
    deviation_pct: float = 0.0
    severity: str = ""
    description: str = ""


class DashboardData(BaseModel):
    """Composed dashboard data for CISO view."""

    overall_score: float = 0.0
    risk_level: str = ""
    domain_scores: dict[str, float] = Field(default_factory=dict)
    top_kpis: list[dict[str, Any]] = Field(default_factory=list)
    active_incidents: int = 0
    open_findings: int = 0
    agents_healthy: int = 0
    agents_total: int = 0
    executive_summary: str = ""


class SecurityDashboardAggregatorState(BaseModel):
    """Full state for the dashboard aggregator workflow."""

    # Input
    tenant_id: str = ""
    request_id: str = ""

    # Pipeline data
    agent_metrics: list[AgentMetric] = Field(default_factory=list)
    domain_aggregates: list[DomainAggregate] = Field(default_factory=list)
    kpis: list[KPICalculation] = Field(default_factory=list)
    anomalies: list[MetricAnomaly] = Field(default_factory=list)
    dashboard_data: DashboardData = Field(default_factory=DashboardData)

    # Metrics
    agents_reporting: int = 0
    data_freshness_seconds: float = 0.0

    # Workflow tracking
    current_stage: AggregatorStage = AggregatorStage.COLLECT_AGENT_METRICS
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
    session_duration_ms: int = 0
