"""API SLA Compliance Tracker. Measure API SLA adherence, detect SLA breach risk, and generate..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ApiSlaComplianceTracker = engine(
    "ApiSlaComplianceTracker",
    description="Measure SLA adherence, detect breach risk, generate compliance reports.",
    enums={
        "compliance_status": EnumDef(
            "ComplianceStatus",
            {
                "COMPLIANT": "compliant",
                "AT_RISK": "at_risk",
                "BREACHED": "breached",
                "EXEMPT": "exempt",
            },
        ),
        "sla_metric": EnumDef(
            "SlaMetric",
            {
                "AVAILABILITY": "availability",
                "LATENCY_P99": "latency_p99",
                "ERROR_RATE": "error_rate",
                "THROUGHPUT": "throughput",
            },
        ),
        "consumer_tier": EnumDef(
            "ConsumerTier",
            {
                "PLATINUM": "platinum",
                "GOLD": "gold",
                "SILVER": "silver",
                "BRONZE": "bronze",
            },
        ),
    },
    record_fields=[
        FieldDef("consumer_id", str, ""),
        FieldDef("target_value", float, 99.9),
        FieldDef("actual_value", float, 99.9),
        FieldDef("breach_margin", float, 0.0),
    ],
    key_field="api_name",
)

# Backward-compatible re-exports
ComplianceStatus = ApiSlaComplianceTracker.ComplianceStatus
SlaMetric = ApiSlaComplianceTracker.SlaMetric
ConsumerTier = ApiSlaComplianceTracker.ConsumerTier
SlaComplianceRecord = ApiSlaComplianceTracker.Record
SlaComplianceAnalysis = ApiSlaComplianceTracker.Analysis
SlaComplianceReport = ApiSlaComplianceTracker.Report
