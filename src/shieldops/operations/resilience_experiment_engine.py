"""ResilienceExperimentEngine — resilience experiment engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ResilienceExperimentEngine = engine(
    "ResilienceExperimentEngine",
    module="operations",  # uses record_item
    description="Resilience Experiment Engine.",
    enums={
        "experiment_category": EnumDef(
            "ExperimentCategory",
            {
                "LATENCY": "latency",
                "FAILURE": "failure",
                "RESOURCE": "resource",
                "NETWORK": "network",
                "STATE": "state",
            },
        ),
        "experiment_status": EnumDef(
            "ExperimentStatus",
            {
                "PLANNED": "planned",
                "RUNNING": "running",
                "COMPLETED": "completed",
                "ABORTED": "aborted",
                "FAILED": "failed",
            },
        ),
        "resilience_outcome": EnumDef(
            "ResilienceOutcome",
            {
                "PASSED": "passed",
                "DEGRADED": "degraded",
                "FAILED": "failed",
                "CASCADING": "cascading",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
ExperimentCategory = ResilienceExperimentEngine.ExperimentCategory
ExperimentStatus = ResilienceExperimentEngine.ExperimentStatus
ResilienceOutcome = ResilienceExperimentEngine.ResilienceOutcome
ResilienceExperimentRecord = ResilienceExperimentEngine.Record
ResilienceExperimentAnalysis = ResilienceExperimentEngine.Analysis
ResilienceExperimentReport = ResilienceExperimentEngine.Report
