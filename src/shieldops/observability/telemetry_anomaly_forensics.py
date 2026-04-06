"""TelemetryAnomalyForensics — anomaly forensics."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TelemetryAnomalyForensics = engine(
    "TelemetryAnomalyForensics",
    description="Telemetry Anomaly Forensics. Performs forensic analysis on telemetry anomal...",
    enums={
        "origin": EnumDef(
            "AnomalyOrigin",
            {
                "INFRASTRUCTURE": "infrastructure",
                "APPLICATION": "application",
                "NETWORK": "network",
                "EXTERNAL": "external",
            },
        ),
        "depth": EnumDef(
            "ForensicDepth",
            {
                "SURFACE": "surface",
                "MODERATE": "moderate",
                "DEEP": "deep",
                "EXHAUSTIVE": "exhaustive",
            },
        ),
        "evidence_type": EnumDef(
            "EvidenceType",
            {
                "METRIC_SPIKE": "metric_spike",
                "LOG_PATTERN": "log_pattern",
                "TRACE_GAP": "trace_gap",
                "CONFIG_CHANGE": "config_change",
            },
        ),
    },
    record_fields=[
        FieldDef("severity", float, 0.0),
        FieldDef("confidence", float, 0.0),
    ],
)

# Backward-compatible re-exports
AnomalyOrigin = TelemetryAnomalyForensics.AnomalyOrigin
ForensicDepth = TelemetryAnomalyForensics.ForensicDepth
EvidenceType = TelemetryAnomalyForensics.EvidenceType
ForensicRecord = TelemetryAnomalyForensics.Record
ForensicAnalysis = TelemetryAnomalyForensics.Analysis
ForensicReport = TelemetryAnomalyForensics.Report
