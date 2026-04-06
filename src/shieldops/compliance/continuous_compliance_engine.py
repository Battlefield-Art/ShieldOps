"""Continuous Compliance Engine — track real-time compliance posture, monitor control effectiv..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ContinuousComplianceEngine = engine(
    "ContinuousComplianceEngine",
    description="Track real-time compliance posture, monitor control effectiveness, detect r...",
    enums={
        "scan_frequency": EnumDef(
            "ScanFrequency",
            {
                "REAL_TIME": "real_time",
                "HOURLY": "hourly",
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "ON_CHANGE": "on_change",
            },
        ),
        "control_category": EnumDef(
            "ControlCategory",
            {
                "ACCESS": "access",
                "ENCRYPTION": "encryption",
                "LOGGING": "logging",
                "NETWORK": "network",
                "DATA_PROTECTION": "data_protection",
            },
        ),
        "finding_trend": EnumDef(
            "FindingTrend",
            {
                "NEW": "new",
                "RECURRING": "recurring",
                "RESOLVED": "resolved",
                "REGRESSED": "regressed",
                "STABLE": "stable",
            },
        ),
    },
    record_fields=[
        FieldDef("framework", str, ""),
        FieldDef("is_compliant", bool, True),
        FieldDef("severity", str, "low"),
        FieldDef("resource_id", str, ""),
        FieldDef("remediation_time_hours", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="control_id",
)

# Backward-compatible re-exports
ScanFrequency = ContinuousComplianceEngine.ScanFrequency
ControlCategory = ContinuousComplianceEngine.ControlCategory
FindingTrend = ContinuousComplianceEngine.FindingTrend
ContinuousComplianceRecord = ContinuousComplianceEngine.Record
ContinuousComplianceAnalysis = ContinuousComplianceEngine.Analysis
ContinuousComplianceReport = ContinuousComplianceEngine.Report
