"""Compute Cost Tracker Engine — compute cost per improvement, detect anomalies, and forecast..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ComputeCostTrackerEngine = engine(
    "ComputeCostTrackerEngine",
    description="Compute cost per improvement, detect anomalies, and forecast total optimiza...",
    enums={
        "category": EnumDef(
            "CostCategory",
            {
                "LLM_API_CALLS": "llm_api_calls",
                "COMPUTE_INFRASTRUCTURE": "compute_infrastructure",
                "EVALUATION_RUNS": "evaluation_runs",
                "DATA_PROCESSING": "data_processing",
            },
        ),
        "efficiency": EnumDef(
            "CostEfficiency",
            {
                "HIGHLY_EFFICIENT": "highly_efficient",
                "EFFICIENT": "efficient",
                "INEFFICIENT": "inefficient",
                "WASTEFUL": "wasteful",
            },
        ),
        "trend": EnumDef(
            "CostTrend",
            {
                "DECREASING": "decreasing",
                "STABLE": "stable",
                "INCREASING": "increasing",
                "SPIKING": "spiking",
            },
        ),
    },
    record_fields=[
        FieldDef("cost_usd", float, 0.0),
        FieldDef("improvement_delta", float, 0.0),
        FieldDef("units_consumed", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="experiment_id",
)

# Backward-compatible re-exports
CostCategory = ComputeCostTrackerEngine.CostCategory
CostEfficiency = ComputeCostTrackerEngine.CostEfficiency
CostTrend = ComputeCostTrackerEngine.CostTrend
ComputeCostRecord = ComputeCostTrackerEngine.Record
ComputeCostAnalysis = ComputeCostTrackerEngine.Analysis
ComputeCostReport = ComputeCostTrackerEngine.Report
