"""Agent Creation Analytics — track creation and adoption."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AgentCreationAnalytics = engine(
    "AgentCreationAnalytics",
    description="Track agent creation rates and adoption.",
    enums={
        "metric": EnumDef(
            "CreationMetric",
            {
                "TIME_TO_CREATE": "time_to_create",
                "LINES_OF_CODE": "lines_of_code",
                "TEST_COVERAGE": "test_coverage",
                "REVIEW_CYCLES": "review_cycles",
            },
        ),
        "quality": EnumDef(
            "QualityTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DEGRADING": "degrading",
                "UNKNOWN": "unknown",
            },
        ),
        "adoption": EnumDef(
            "AdoptionRate",
            {
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
                "NONE": "none",
            },
        ),
    },
    key_field="agent_name",
)

# Backward-compatible re-exports
CreationMetric = AgentCreationAnalytics.CreationMetric
QualityTrend = AgentCreationAnalytics.QualityTrend
AdoptionRate = AgentCreationAnalytics.AdoptionRate
CreationRecord = AgentCreationAnalytics.Record
CreationAnalysis = AgentCreationAnalytics.Analysis
CreationReport = AgentCreationAnalytics.Report
