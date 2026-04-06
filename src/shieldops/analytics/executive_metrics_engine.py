"""ExecutiveMetricsEngine -- executive-level metrics."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ExecutiveMetricsEngine = engine(
    "ExecutiveMetricsEngine",
    description="Collect and aggregate executive metrics.",
    enums={
        "category": EnumDef(
            "MetricCategory",
            {
                "RISK": "risk",
                "COMPLIANCE": "compliance",
                "OPERATIONAL": "operational",
                "FINANCIAL": "financial",
                "COVERAGE": "coverage",
            },
        ),
        "audience": EnumDef(
            "AudienceLevel",
            {
                "CISO": "ciso",
                "VP": "vp",
                "DIRECTOR": "director",
                "MANAGER": "manager",
                "BOARD": "board",
            },
        ),
        "frequency": EnumDef(
            "ReportFrequency",
            {
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
                "QUARTERLY": "quarterly",
            },
        ),
    },
    record_fields=[
        FieldDef("metric_value", float, 0.0),
        FieldDef("unit", str, ""),
    ],
)

# Backward-compatible re-exports
MetricCategory = ExecutiveMetricsEngine.MetricCategory
AudienceLevel = ExecutiveMetricsEngine.AudienceLevel
ReportFrequency = ExecutiveMetricsEngine.ReportFrequency
ExecutiveMetricsRecord = ExecutiveMetricsEngine.Record
ExecutiveMetricsAnalysis = ExecutiveMetricsEngine.Analysis
ExecutiveMetricsReport = ExecutiveMetricsEngine.Report
