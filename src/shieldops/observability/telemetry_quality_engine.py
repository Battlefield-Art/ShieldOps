"""TelemetryQualityEngine — telemetry quality engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

TelemetryQualityEngine = engine(
    "TelemetryQualityEngine",
    module="operations",  # uses record_item
    description="Telemetry Quality Engine.",
    enums={
        "quality_dimension": EnumDef(
            "QualityDimension",
            {
                "COMPLETENESS": "completeness",
                "ACCURACY": "accuracy",
                "TIMELINESS": "timeliness",
                "CONSISTENCY": "consistency",
                "RELEVANCE": "relevance",
            },
        ),
        "telemetry_type": EnumDef(
            "TelemetryType",
            {
                "METRIC": "metric",
                "LOG": "log",
                "TRACE": "trace",
                "EVENT": "event",
                "PROFILE": "profile",
            },
        ),
        "quality_grade": EnumDef(
            "QualityGrade",
            {
                "A": "a",
                "B": "b",
                "C": "c",
                "D": "d",
                "F": "f",
            },
        ),
    },
)

# Backward-compatible re-exports
QualityDimension = TelemetryQualityEngine.QualityDimension
TelemetryType = TelemetryQualityEngine.TelemetryType
QualityGrade = TelemetryQualityEngine.QualityGrade
TelemetryQualityEngineRecord = TelemetryQualityEngine.Record
TelemetryQualityEngineAnalysis = TelemetryQualityEngine.Analysis
TelemetryQualityEngineReport = TelemetryQualityEngine.Report
