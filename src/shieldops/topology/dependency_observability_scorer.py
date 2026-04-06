"""DependencyObservabilityScorer — dependency observability scorer."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

DependencyObservabilityScorer = engine(
    "DependencyObservabilityScorer",
    module="operations",  # uses record_item
    description="Dependency Observability Scorer.",
    enums={
        "observability_dimension": EnumDef(
            "ObservabilityDimension",
            {
                "METRICS": "metrics",
                "LOGS": "logs",
                "TRACES": "traces",
                "HEALTH_CHECKS": "health_checks",
                "ALERTING": "alerting",
            },
        ),
        "dependency_type": EnumDef(
            "DependencyType",
            {
                "SYNCHRONOUS": "synchronous",
                "ASYNCHRONOUS": "asynchronous",
                "DATABASE": "database",
                "CACHE": "cache",
                "EXTERNAL": "external",
            },
        ),
        "score_level": EnumDef(
            "ScoreLevel",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
                "CRITICAL": "critical",
            },
        ),
    },
)

# Backward-compatible re-exports
ObservabilityDimension = DependencyObservabilityScorer.ObservabilityDimension
DependencyType = DependencyObservabilityScorer.DependencyType
ScoreLevel = DependencyObservabilityScorer.ScoreLevel
DependencyObservabilityScorerRecord = DependencyObservabilityScorer.Record
DependencyObservabilityScorerAnalysis = DependencyObservabilityScorer.Analysis
DependencyObservabilityScorerReport = DependencyObservabilityScorer.Report
