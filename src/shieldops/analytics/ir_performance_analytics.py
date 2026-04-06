"""IR Performance Analytics — measure IR response metrics."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IRPerformanceAnalyticsEngine = engine(
    "IRPerformanceAnalyticsEngine",
    description="Measure and analyze IR response metrics.",
    enums={
        "metric": EnumDef(
            "IRMetric",
            {
                "MTTR": "mttr",
                "MTTD": "mttd",
                "MTTC": "mttc",
                "MTTE": "mtte",
                "MTTR_FULL": "mttr_full",
            },
        ),
        "speed": EnumDef(
            "ResponseSpeed",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "ACCEPTABLE": "acceptable",
                "SLOW": "slow",
                "CRITICAL": "critical",
            },
        ),
        "trend": EnumDef(
            "OutcomeTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DEGRADING": "degrading",
                "VOLATILE": "volatile",
                "UNKNOWN": "unknown",
            },
        ),
    },
    record_fields=[
        FieldDef("value_minutes", float, 0.0),
        FieldDef("target_minutes", float, 0.0),
        FieldDef("incident_type", str, ""),
    ],
    key_field="incident_id",
)

# Backward-compatible re-exports
IRMetric = IRPerformanceAnalyticsEngine.IRMetric
ResponseSpeed = IRPerformanceAnalyticsEngine.ResponseSpeed
OutcomeTrend = IRPerformanceAnalyticsEngine.OutcomeTrend
IRPerformanceRecord = IRPerformanceAnalyticsEngine.Record
IRPerformanceAnalysis = IRPerformanceAnalyticsEngine.Analysis
IRPerformanceReport = IRPerformanceAnalyticsEngine.Report
