"""Cloud Cost Anomaly Detector Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CCADStage(StrEnum):
    COLLECT_BILLING = "collect_billing"
    ANALYZE_TRENDS = "analyze_trends"
    DETECT_ANOMALIES = "detect_anomalies"
    CLASSIFY_CAUSE = "classify_cause"
    ALERT = "alert"
    REPORT = "report"


class AnomalyType(StrEnum):
    SPIKE = "spike"
    DRIFT = "drift"
    WASTE = "waste"
    MISCONFIG = "misconfig"
    ORPHAN_RESOURCE = "orphan_resource"
    RESERVED_UNUSED = "reserved_unused"


class CloudProvider(StrEnum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    ON_PREM = "on_prem"
    MULTI = "multi"


class BillingRecord(BaseModel):
    """A single cloud billing line item."""

    id: str = ""
    timestamp: str = ""
    provider: CloudProvider = CloudProvider.AWS
    account_id: str = ""
    service: str = ""
    region: str = ""
    cost_usd: float = 0.0
    usage_quantity: float = 0.0
    usage_unit: str = ""
    tags: dict[str, str] = Field(default_factory=dict)


class SpendTrend(BaseModel):
    """An observed spending trend over time."""

    id: str = ""
    service: str = ""
    provider: CloudProvider = CloudProvider.AWS
    period_days: int = 30
    avg_daily_cost: float = 0.0
    current_daily_cost: float = 0.0
    change_pct: float = 0.0
    forecast_monthly: float = 0.0
    trend_direction: str = "stable"


class CostAnomaly(BaseModel):
    """A detected cost anomaly."""

    id: str = ""
    anomaly_type: AnomalyType = AnomalyType.SPIKE
    service: str = ""
    provider: CloudProvider = CloudProvider.AWS
    expected_cost: float = 0.0
    actual_cost: float = 0.0
    deviation_pct: float = 0.0
    severity: str = "medium"
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)


class CauseClassification(BaseModel):
    """Root-cause classification for an anomaly."""

    id: str = ""
    anomaly_id: str = ""
    root_cause: str = ""
    category: AnomalyType = AnomalyType.SPIKE
    recommendation: str = ""
    estimated_savings_usd: float = 0.0
    auto_remediable: bool = False


class AlertRecord(BaseModel):
    """An alert sent for a cost anomaly."""

    id: str = ""
    anomaly_id: str = ""
    channel: str = ""
    status: str = ""
    recipient: str = ""
    sent_at: str = ""
    acknowledged: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudCostAnomalyDetectorState(BaseModel):
    """Main state for the Cloud Cost Anomaly Detector agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CCADStage = CCADStage.COLLECT_BILLING

    billing_records: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    spend_trends: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    anomalies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    alerts: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    report: str = ""
    total_spend_analyzed: float = 0.0
    anomalies_detected: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
