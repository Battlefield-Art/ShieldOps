"""Cloud Contract Optimizer analyze contract terms, identify negotiation leverage, model contr..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CloudContractOptimizer = engine(
    "CloudContractOptimizer",
    description="Analyze contract terms, identify leverage, model contract scenarios.",
    enums={
        "contract_type": EnumDef(
            "ContractType",
            {
                "ON_DEMAND": "on_demand",
                "ENTERPRISE": "enterprise",
                "RESERVED": "reserved",
                "CUSTOM": "custom",
            },
        ),
        "leverage_type": EnumDef(
            "LeverageType",
            {
                "VOLUME": "volume",
                "COMMITMENT": "commitment",
                "MULTI_YEAR": "multi_year",
                "BUNDLING": "bundling",
            },
        ),
        "scenario_outcome": EnumDef(
            "ScenarioOutcome",
            {
                "FAVORABLE": "favorable",
                "NEUTRAL": "neutral",
                "UNFAVORABLE": "unfavorable",
                "RISKY": "risky",
            },
        ),
    },
    record_fields=[
        FieldDef("annual_value", float, 0.0),
        FieldDef("discount_pct", float, 0.0),
        FieldDef("term_months", int, 12),
        FieldDef("description", str, ""),
    ],
    key_field="contract_id",
)

# Backward-compatible re-exports
ContractType = CloudContractOptimizer.ContractType
LeverageType = CloudContractOptimizer.LeverageType
ScenarioOutcome = CloudContractOptimizer.ScenarioOutcome
ContractRecord = CloudContractOptimizer.Record
ContractAnalysis = CloudContractOptimizer.Analysis
ContractReport = CloudContractOptimizer.Report
