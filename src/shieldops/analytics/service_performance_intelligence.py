"""ServicePerformanceIntelligence — service performance intelligence."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ServicePerformanceIntelligence = engine(
    "ServicePerformanceIntelligence",
    module="operations",  # uses record_item
    description="Service Performance Intelligence.",
    enums={
        "performance_dimension": EnumDef(
            "PerformanceDimension",
            {
                "LATENCY": "latency",
                "THROUGHPUT": "throughput",
                "ERROR_RATE": "error_rate",
                "SATURATION": "saturation",
                "AVAILABILITY": "availability",
            },
        ),
        "analysis_scope": EnumDef(
            "AnalysisScope",
            {
                "SERVICE": "service",
                "ENDPOINT": "endpoint",
                "DEPENDENCY": "dependency",
                "INFRASTRUCTURE": "infrastructure",
                "USER_JOURNEY": "user_journey",
            },
        ),
        "performance_trend": EnumDef(
            "PerformanceTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DEGRADING": "degrading",
                "VOLATILE": "volatile",
                "ANOMALOUS": "anomalous",
            },
        ),
    },
)

# Backward-compatible re-exports
PerformanceDimension = ServicePerformanceIntelligence.PerformanceDimension
AnalysisScope = ServicePerformanceIntelligence.AnalysisScope
PerformanceTrend = ServicePerformanceIntelligence.PerformanceTrend
ServicePerformanceIntelligenceRecord = ServicePerformanceIntelligence.Record
ServicePerformanceIntelligenceAnalysis = ServicePerformanceIntelligence.Analysis
ServicePerformanceIntelligenceReport = ServicePerformanceIntelligence.Report
