"""Observability Cost Optimizer — observability cost optimization and spend management."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ObservabilityCostOptimizer = engine(
    "ObservabilityCostOptimizer",
    description="Observability Cost Optimizer — observability cost optimization and spend ma...",
    enums={
        "cost_category": EnumDef(
            "CostCategory",
            {
                "METRICS": "metrics",
                "LOGS": "logs",
                "TRACES": "traces",
                "SYNTHETICS": "synthetics",
                "INFRASTRUCTURE": "infrastructure",
            },
        ),
        "optimization_source": EnumDef(
            "OptimizationSource",
            {
                "VENDOR_API": "vendor_api",
                "USAGE_ANALYSIS": "usage_analysis",
                "BENCHMARK": "benchmark",
                "RECOMMENDATION": "recommendation",
                "CUSTOM": "custom",
            },
        ),
        "savings_level": EnumDef(
            "SavingsLevel",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "MINIMAL": "minimal",
                "NONE": "none",
            },
        ),
    },
)

# Backward-compatible re-exports
CostCategory = ObservabilityCostOptimizer.CostCategory
OptimizationSource = ObservabilityCostOptimizer.OptimizationSource
SavingsLevel = ObservabilityCostOptimizer.SavingsLevel
ObsCostRecord = ObservabilityCostOptimizer.Record
ObsCostAnalysis = ObservabilityCostOptimizer.Analysis
ObservabilityCostReport = ObservabilityCostOptimizer.Report
