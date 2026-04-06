"""Real Time Anomaly Correlator — real-time anomaly correlation across multiple signals."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

RealTimeAnomalyCorrelator = engine(
    "RealTimeAnomalyCorrelator",
    description="Real Time Anomaly Correlator — real-time anomaly correlation across multipl...",
    enums={
        "anomaly_type": EnumDef(
            "AnomalyType",
            {
                "SPIKE": "spike",
                "DROP": "drop",
                "DRIFT": "drift",
                "PATTERN_BREAK": "pattern_break",
                "SEASONAL": "seasonal",
            },
        ),
        "anomaly_source": EnumDef(
            "AnomalySource",
            {
                "METRIC_STREAM": "metric_stream",
                "LOG_PIPELINE": "log_pipeline",
                "TRACE_ANALYSIS": "trace_analysis",
                "USER_REPORT": "user_report",
                "ML_MODEL": "ml_model",
            },
        ),
        "anomaly_correlation": EnumDef(
            "AnomalyCorrelation",
            {
                "CONFIRMED": "confirmed",
                "PROBABLE": "probable",
                "POSSIBLE": "possible",
                "COINCIDENTAL": "coincidental",
                "UNRELATED": "unrelated",
            },
        ),
    },
)

# Backward-compatible re-exports
AnomalyType = RealTimeAnomalyCorrelator.AnomalyType
AnomalySource = RealTimeAnomalyCorrelator.AnomalySource
AnomalyCorrelation = RealTimeAnomalyCorrelator.AnomalyCorrelation
AnomalyRecord = RealTimeAnomalyCorrelator.Record
AnomalyAnalysis = RealTimeAnomalyCorrelator.Analysis
RealTimeAnomalyReport = RealTimeAnomalyCorrelator.Report
