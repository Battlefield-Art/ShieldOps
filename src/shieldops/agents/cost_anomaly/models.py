"""State models for the Cost Anomaly Detector Agent LangGraph workflow."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DetectorStage(StrEnum):
    """Stages in the cost anomaly detection workflow."""

    COLLECT_BILLING = "collect_billing"
    DETECT_ANOMALIES = "detect_anomalies"
    CLASSIFY_WASTE = "classify_waste"
    ANALYZE_LLM_COSTS = "analyze_llm_costs"
    RECOMMEND = "recommend"
    REPORT = "report"


class AnomalyType(StrEnum):
    """Types of cost anomalies detected."""

    COST_SPIKE = "cost_spike"
    BILLING_ERROR = "billing_error"
    RESOURCE_WASTE = "resource_waste"
    LLM_OVERRUN = "llm_overrun"
    UNUSED_RESOURCE = "unused_resource"
    RIGHTS_SIZING = "rights_sizing"


class CostSeverity(StrEnum):
    """Severity levels for cost anomalies."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CloudService(StrEnum):
    """Cloud services monitored for cost anomalies."""

    AWS_EC2 = "aws_ec2"
    AWS_RDS = "aws_rds"
    AWS_S3 = "aws_s3"
    GCP_COMPUTE = "gcp_compute"
    GCP_BIGQUERY = "gcp_bigquery"
    AZURE_VM = "azure_vm"
    KUBERNETES = "kubernetes"
    LLM_API = "llm_api"


class CostDataPoint(BaseModel):
    """A single cost data point from billing systems."""

    id: str = ""
    service: CloudService = CloudService.AWS_EC2
    resource_id: str = ""
    daily_cost: float = 0.0
    monthly_forecast: float = 0.0
    budget_pct: float = 0.0
    region: str = ""
    tags: dict[str, str] = Field(default_factory=dict)
    timestamp: float = 0.0


class CostAnomaly(BaseModel):
    """A detected cost anomaly."""

    id: str = ""
    service: CloudService = CloudService.AWS_EC2
    resource_id: str = ""
    anomaly_type: AnomalyType = AnomalyType.COST_SPIKE
    severity: CostSeverity = CostSeverity.MEDIUM
    description: str = ""
    expected_cost: float = 0.0
    actual_cost: float = 0.0
    deviation_pct: float = 0.0
    first_detected: float = 0.0


class WasteClassification(BaseModel):
    """A resource waste classification."""

    id: str = ""
    resource_id: str = ""
    service: CloudService = CloudService.AWS_EC2
    waste_type: str = ""
    monthly_waste: float = 0.0
    utilization_pct: float = 0.0
    recommendation: str = ""
    savings_potential: float = 0.0


class CostRecommendation(BaseModel):
    """An actionable cost optimization recommendation."""

    id: str = ""
    anomaly_id: str = ""
    action: str = ""
    target: str = ""
    description: str = ""
    estimated_savings: float = 0.0
    auto_executable: bool = False
    priority: str = "medium"


class ReasoningStep(BaseModel):
    """Audit trail entry for the cost anomaly detection workflow."""

    step: int = 0
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CostAnomalyState(BaseModel):
    """Full state for a Cost Anomaly Detector workflow run."""

    # Input
    request_id: str = ""
    stage: DetectorStage = DetectorStage.COLLECT_BILLING
    tenant_id: str = ""

    # Billing data
    cost_data: list[CostDataPoint] = Field(default_factory=list)

    # Detection results
    anomalies: list[CostAnomaly] = Field(default_factory=list)
    waste_classifications: list[WasteClassification] = Field(default_factory=list)
    llm_cost_analysis: dict[str, Any] = Field(default_factory=dict)

    # Recommendations
    recommendations: list[CostRecommendation] = Field(default_factory=list)
    total_monthly_waste: float = 0.0

    # Stats and tracking
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str | None = None
