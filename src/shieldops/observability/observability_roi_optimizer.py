"""ObservabilityRoiOptimizer — ROI optimization engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ObservabilityRoiOptimizer = engine(
    "ObservabilityRoiOptimizer",
    description="Observability ROI Optimizer. Analyzes the return on investment for observab...",
    enums={
        "signal_value": EnumDef(
            "SignalValue",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "cost_category": EnumDef(
            "CostCategory",
            {
                "INGESTION": "ingestion",
                "STORAGE": "storage",
                "QUERY": "query",
                "EXPORT": "export",
            },
        ),
        "optimization_action": EnumDef(
            "OptimizationAction",
            {
                "DOWNSAMPLE": "downsample",
                "AGGREGATE": "aggregate",
                "ARCHIVE": "archive",
                "DROP": "drop",
            },
        ),
    },
    record_fields=[
        FieldDef("monthly_cost_usd", float, 0.0),
        FieldDef("usage_frequency", float, 0.0),
    ],
)

# Backward-compatible re-exports
SignalValue = ObservabilityRoiOptimizer.SignalValue
CostCategory = ObservabilityRoiOptimizer.CostCategory
OptimizationAction = ObservabilityRoiOptimizer.OptimizationAction
RoiRecord = ObservabilityRoiOptimizer.Record
RoiAnalysis = ObservabilityRoiOptimizer.Analysis
RoiReport = ObservabilityRoiOptimizer.Report
