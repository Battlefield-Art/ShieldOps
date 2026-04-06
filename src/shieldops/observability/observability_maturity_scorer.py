"""Observability Maturity Scorer — observability maturity assessment and scoring."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ObservabilityMaturityScorer = engine(
    "ObservabilityMaturityScorer",
    description="Observability Maturity Scorer — observability maturity assessment and scoring.",
    enums={
        "maturity_dimension": EnumDef(
            "MaturityDimension",
            {
                "METRICS": "metrics",
                "LOGGING": "logging",
                "TRACING": "tracing",
                "ALERTING": "alerting",
                "DASHBOARDS": "dashboards",
            },
        ),
        "maturity_source": EnumDef(
            "MaturitySource",
            {
                "AUTOMATED_SCAN": "automated_scan",
                "MANUAL_REVIEW": "manual_review",
                "BENCHMARK": "benchmark",
                "SURVEY": "survey",
                "INTEGRATION": "integration",
            },
        ),
        "maturity_level": EnumDef(
            "MaturityLevel",
            {
                "ADVANCED": "advanced",
                "INTERMEDIATE": "intermediate",
                "BASIC": "basic",
                "INITIAL": "initial",
                "ABSENT": "absent",
            },
        ),
    },
)

# Backward-compatible re-exports
MaturityDimension = ObservabilityMaturityScorer.MaturityDimension
MaturitySource = ObservabilityMaturityScorer.MaturitySource
MaturityLevel = ObservabilityMaturityScorer.MaturityLevel
MaturityRecord = ObservabilityMaturityScorer.Record
MaturityAnalysis = ObservabilityMaturityScorer.Analysis
ObservabilityMaturityReport = ObservabilityMaturityScorer.Report
