"""TelemetryComplianceEngine — telemetry compliance."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TelemetryComplianceEngine = engine(
    "TelemetryComplianceEngine",
    description="Telemetry Compliance Engine. Ensures telemetry data meets compliance requir...",
    enums={
        "standard": EnumDef(
            "ComplianceStandard",
            {
                "GDPR": "gdpr",
                "HIPAA": "hipaa",
                "SOX": "sox",
                "PCI": "pci",
            },
        ),
        "sensitivity": EnumDef(
            "DataSensitivity",
            {
                "PUBLIC": "public",
                "INTERNAL": "internal",
                "CONFIDENTIAL": "confidential",
                "RESTRICTED": "restricted",
            },
        ),
        "retention": EnumDef(
            "RetentionPolicy",
            {
                "DAYS_30": "days_30",
                "DAYS_90": "days_90",
                "DAYS_365": "days_365",
                "INDEFINITE": "indefinite",
            },
        ),
    },
    record_fields=[
        FieldDef("pii_detected", bool, False),
        FieldDef("region", str, ""),
    ],
)

# Backward-compatible re-exports
ComplianceStandard = TelemetryComplianceEngine.ComplianceStandard
DataSensitivity = TelemetryComplianceEngine.DataSensitivity
RetentionPolicy = TelemetryComplianceEngine.RetentionPolicy
ComplianceRecord = TelemetryComplianceEngine.Record
ComplianceAnalysis = TelemetryComplianceEngine.Analysis
ComplianceReport = TelemetryComplianceEngine.Report
