"""SteadyStateHypothesisEngine — steady state hypothesis engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SteadyStateHypothesisEngine = engine(
    "SteadyStateHypothesisEngine",
    description="Steady State Hypothesis Engine.",
    enums={
        "hypothesis_type": EnumDef(
            "HypothesisType",
            {
                "AVAILABILITY": "availability",
                "LATENCY": "latency",
                "THROUGHPUT": "throughput",
                "ERROR_RATE": "error_rate",
                "RESOURCE_USAGE": "resource_usage",
            },
        ),
        "validation_result": EnumDef(
            "ValidationResult",
            {
                "CONFIRMED": "confirmed",
                "VIOLATED": "violated",
                "INCONCLUSIVE": "inconclusive",
                "PARTIAL": "partial",
                "SKIPPED": "skipped",
            },
        ),
        "steady_state_scope": EnumDef(
            "SteadyStateScope",
            {
                "SERVICE": "service",
                "CLUSTER": "cluster",
                "REGION": "region",
                "GLOBAL": "global",
                "NAMESPACE": "namespace",
            },
        ),
    },
)

# Backward-compatible re-exports
HypothesisType = SteadyStateHypothesisEngine.HypothesisType
ValidationResult = SteadyStateHypothesisEngine.ValidationResult
SteadyStateScope = SteadyStateHypothesisEngine.SteadyStateScope
SteadyStateRecord = SteadyStateHypothesisEngine.Record
SteadyStateAnalysis = SteadyStateHypothesisEngine.Analysis
SteadyStateReport = SteadyStateHypothesisEngine.Report
