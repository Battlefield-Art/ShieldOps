"""DetectionEngineeringMetrics — track detection engineering metrics and rule effectiveness."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

DetectionEngineeringMetrics = engine(
    "DetectionEngineeringMetrics",
    description="Track detection engineering metrics and rule effectiveness.",
    enums={
        "record_type": EnumDef(
            "DetectionType",
            {
                "METRIC": "metric",
                "TREND": "trend",
                "FORECAST": "forecast",
                "ANOMALY": "anomaly",
                "BENCHMARK": "benchmark",
            },
        ),
        "source": EnumDef(
            "DetectionSource",
            {
                "TELEMETRY": "telemetry",
                "LOG_ANALYSIS": "log_analysis",
                "APM": "apm",
                "CUSTOM": "custom",
                "SYNTHETIC": "synthetic",
            },
        ),
        "level": EnumDef(
            "DetectionLevel",
            {
                "CRITICAL": "critical",
                "WARNING": "warning",
                "NORMAL": "normal",
                "OPTIMAL": "optimal",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
DetectionType = DetectionEngineeringMetrics.DetectionType
DetectionSource = DetectionEngineeringMetrics.DetectionSource
DetectionLevel = DetectionEngineeringMetrics.DetectionLevel
DetectionRecord = DetectionEngineeringMetrics.Record
DetectionAnalysis = DetectionEngineeringMetrics.Analysis
DetectionReport = DetectionEngineeringMetrics.Report
