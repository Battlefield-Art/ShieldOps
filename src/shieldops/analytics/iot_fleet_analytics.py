"""IoT Fleet Analytics — analyze fleet health, compliance, and risk trends."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IoTFleetAnalytics = engine(
    "IoTFleetAnalytics",
    description="Analyze IoT fleet health, compliance, and risk trends.",
    enums={
        "metric": EnumDef(
            "FleetMetric",
            {
                "DEVICE_UPTIME": "device_uptime",
                "FIRMWARE_CURRENCY": "firmware_currency",
                "COMMUNICATION_HEALTH": "communication_health",
                "PATCH_COMPLIANCE": "patch_compliance",
                "ANOMALY_RATE": "anomaly_rate",
            },
        ),
        "compliance": EnumDef(
            "ComplianceRate",
            {
                "FULLY_COMPLIANT": "fully_compliant",
                "MOSTLY_COMPLIANT": "mostly_compliant",
                "PARTIALLY_COMPLIANT": "partially_compliant",
                "NON_COMPLIANT": "non_compliant",
                "UNKNOWN": "unknown",
            },
        ),
        "threat_trend": EnumDef(
            "ThreatTrend",
            {
                "DECREASING": "decreasing",
                "STABLE": "stable",
                "INCREASING": "increasing",
                "SPIKE": "spike",
                "CRITICAL": "critical",
            },
        ),
    },
    record_fields=[
        FieldDef("device_count", int, 0),
        FieldDef("healthy_count", int, 0),
        FieldDef("anomaly_count", int, 0),
        FieldDef("value", float, 0.0),
    ],
    key_field="fleet_id",
)

# Backward-compatible re-exports
FleetMetric = IoTFleetAnalytics.FleetMetric
ComplianceRate = IoTFleetAnalytics.ComplianceRate
ThreatTrend = IoTFleetAnalytics.ThreatTrend
FleetAnalyticsRecord = IoTFleetAnalytics.Record
FleetAnalysis = IoTFleetAnalytics.Analysis
FleetAnalyticsReport = IoTFleetAnalytics.Report
