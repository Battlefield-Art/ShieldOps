"""Log Analytics Intelligence — intelligent log analytics with pattern detection and clustering."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

LogAnalyticsIntelligence = engine(
    "LogAnalyticsIntelligence",
    description="Log Analytics Intelligence intelligent log analytics with pattern detection...",
    enums={
        "log_pattern_type": EnumDef(
            "LogPatternType",
            {
                "ERROR_CLUSTER": "error_cluster",
                "ANOMALY": "anomaly",
                "TREND_SHIFT": "trend_shift",
                "CORRELATION": "correlation",
                "OUTLIER": "outlier",
            },
        ),
        "log_source": EnumDef(
            "LogSource",
            {
                "APPLICATION": "application",
                "INFRASTRUCTURE": "infrastructure",
                "SECURITY": "security",
                "AUDIT": "audit",
                "SYSTEM": "system",
            },
        ),
        "pattern_confidence": EnumDef(
            "PatternConfidence",
            {
                "CONFIRMED": "confirmed",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "SPECULATIVE": "speculative",
            },
        ),
    },
)

# Backward-compatible re-exports
LogPatternType = LogAnalyticsIntelligence.LogPatternType
LogSource = LogAnalyticsIntelligence.LogSource
PatternConfidence = LogAnalyticsIntelligence.PatternConfidence
LogPatternRecord = LogAnalyticsIntelligence.Record
LogPatternAnalysis = LogAnalyticsIntelligence.Analysis
LogAnalyticsReport = LogAnalyticsIntelligence.Report
