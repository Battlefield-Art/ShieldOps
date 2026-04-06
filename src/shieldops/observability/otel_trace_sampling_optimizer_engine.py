"""OTelTraceSamplingOptimizerEngine — optimize trace sampling rates to balance cost vs. fidelity."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OTelTraceSamplingOptimizerEngine = engine(
    "OTelTraceSamplingOptimizerEngine",
    description="Optimize trace sampling rates to balance cost vs. fidelity.",
    enums={
        "sampling_strategy": EnumDef(
            "SamplingStrategy",
            {
                "FULL_FIDELITY": "full_fidelity",
                "HEAD_BASED": "head_based",
                "TAIL_BASED": "tail_based",
                "ADAPTIVE": "adaptive",
                "PRIORITY_BASED": "priority_based",
            },
        ),
        "trace_importance": EnumDef(
            "TraceImportance",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "NORMAL": "normal",
                "LOW": "low",
                "NOISE": "noise",
            },
        ),
        "sampling_optimization": EnumDef(
            "SamplingOptimization",
            {
                "COST_OPTIMIZED": "cost_optimized",
                "FIDELITY_OPTIMIZED": "fidelity_optimized",
                "BALANCED": "balanced",
                "INCIDENT_FOCUSED": "incident_focused",
            },
        ),
    },
    record_fields=[
        FieldDef("current_rate", float, 1.0),
        FieldDef("traces_per_second", float, 0.0),
        FieldDef("cost_per_day_usd", float, 0.0),
    ],
    key_field="service_name",
)

# Backward-compatible re-exports
SamplingStrategy = OTelTraceSamplingOptimizerEngine.SamplingStrategy
TraceImportance = OTelTraceSamplingOptimizerEngine.TraceImportance
SamplingOptimization = OTelTraceSamplingOptimizerEngine.SamplingOptimization
TraceSamplingRecord = OTelTraceSamplingOptimizerEngine.Record
TraceSamplingAnalysis = OTelTraceSamplingOptimizerEngine.Analysis
TraceSamplingReport = OTelTraceSamplingOptimizerEngine.Report
