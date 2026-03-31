"""Cloud Billing Protector Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CBPStage(StrEnum):
    COLLECT_BILLING = "collect_billing"
    ANALYZE_PATTERNS = "analyze_patterns"
    DETECT_ANOMALIES = "detect_anomalies"
    CLASSIFY_FRAUD = "classify_fraud"
    ENFORCE_LIMITS = "enforce_limits"
    REPORT = "report"


class FraudType(StrEnum):
    CRYPTOMINING = "cryptomining"
    RESOURCE_HIJACKING = "resource_hijacking"
    CREDENTIAL_ABUSE = "credential_abuse"
    DATA_EXFILTRATION = "data_exfiltration"
    SHADOW_RESOURCE = "shadow_resource"
    BUDGET_OVERRUN = "budget_overrun"


class AnomalySeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class BillingRecord(BaseModel):
    """A cloud billing record."""

    id: str = ""
    account_id: str = ""
    service: str = ""
    region: str = ""
    resource_id: str = ""
    cost_usd: float = 0.0
    usage_quantity: float = 0.0
    usage_unit: str = ""
    timestamp: str = ""
    tags: dict[str, str] = Field(default_factory=dict)


class SpendPattern(BaseModel):
    """An analyzed spending pattern."""

    id: str = ""
    account_id: str = ""
    service: str = ""
    avg_daily_cost: float = 0.0
    current_daily_cost: float = 0.0
    deviation_pct: float = 0.0
    trend: str = "stable"
    period_days: int = 30


class BillingAnomaly(BaseModel):
    """A detected billing anomaly."""

    id: str = ""
    account_id: str = ""
    service: str = ""
    resource_id: str = ""
    severity: AnomalySeverity = AnomalySeverity.MEDIUM
    anomaly_type: str = ""
    expected_cost: float = 0.0
    actual_cost: float = 0.0
    excess_cost: float = 0.0
    detection_method: str = ""


class FraudClassification(BaseModel):
    """Fraud classification result."""

    id: str = ""
    anomaly_id: str = ""
    fraud_type: FraudType = FraudType.BUDGET_OVERRUN
    confidence: float = 0.0
    indicators: list[str] = Field(default_factory=list)
    estimated_loss: float = 0.0
    is_confirmed: bool = False


class EnforcementAction(BaseModel):
    """An enforcement action taken."""

    id: str = ""
    anomaly_id: str = ""
    action_type: str = ""
    status: str = ""
    resource_affected: str = ""
    budget_limit_set: float = 0.0
    auto_terminated: bool = False
    rollback_available: bool = True


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudBillingProtectorState(BaseModel):
    """Main state for the Cloud Billing Protector agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CBPStage = CBPStage.COLLECT_BILLING

    billing_records: list[BillingRecord] = Field(default_factory=list)
    patterns: list[SpendPattern] = Field(default_factory=list)
    anomalies: list[BillingAnomaly] = Field(default_factory=list)
    fraud_classifications: list[FraudClassification] = Field(
        default_factory=list,
    )
    enforcements: list[EnforcementAction] = Field(default_factory=list)

    report: str = ""
    total_spend_analyzed: float = 0.0
    anomalies_detected: int = 0

    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
