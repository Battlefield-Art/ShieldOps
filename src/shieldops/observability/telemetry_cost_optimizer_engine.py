"""TelemetryCostOptimizerEngine — optimize overall telemetry pipeline cost, identify waste, re..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TelemetryCostOptimizerEngine = engine(
    "TelemetryCostOptimizerEngine",
    description="Optimize overall telemetry pipeline cost — identify waste, recommend reduct...",
    enums={
        "cost_category": EnumDef(
            "CostCategory",
            {
                "COLLECTION": "collection",
                "PROCESSING": "processing",
                "STORAGE": "storage",
                "EXPORT": "export",
            },
        ),
        "optimization_strategy": EnumDef(
            "OptimizationStrategy",
            {
                "DROP_LOW_VALUE": "drop_low_value",
                "AGGREGATE": "aggregate",
                "DOWNSAMPLE": "downsample",
                "COMPRESS": "compress",
            },
        ),
        "savings_status": EnumDef(
            "SavingsStatus",
            {
                "PROJECTED": "projected",
                "REALIZED": "realized",
                "MISSED": "missed",
                "REVERTED": "reverted",
            },
        ),
    },
    record_fields=[
        FieldDef("cost_usd", float, 0.0),
        FieldDef("projected_savings_usd", float, 0.0),
        FieldDef("realized_savings_usd", float, 0.0),
    ],
    key_field="pipeline_name",
)

# Backward-compatible re-exports
CostCategory = TelemetryCostOptimizerEngine.CostCategory
OptimizationStrategy = TelemetryCostOptimizerEngine.OptimizationStrategy
SavingsStatus = TelemetryCostOptimizerEngine.SavingsStatus
TelemetryCostRecord = TelemetryCostOptimizerEngine.Record
TelemetryCostAnalysis = TelemetryCostOptimizerEngine.Analysis
TelemetryCostReport = TelemetryCostOptimizerEngine.Report
