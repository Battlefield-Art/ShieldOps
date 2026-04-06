"""PlatformEfficiencyOptimizer — platform efficiency optimizer."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PlatformEfficiencyOptimizer = engine(
    "PlatformEfficiencyOptimizer",
    module="operations",  # uses record_item
    description="Platform Efficiency Optimizer.",
    enums={
        "efficiency_domain": EnumDef(
            "EfficiencyDomain",
            {
                "COMPUTE": "compute",
                "STORAGE": "storage",
                "NETWORK": "network",
                "LICENSE": "license",
                "OPERATIONS": "operations",
            },
        ),
        "optimization_action": EnumDef(
            "OptimizationAction",
            {
                "RIGHTSIZE": "rightsize",
                "ELIMINATE": "eliminate",
                "CONSOLIDATE": "consolidate",
                "NEGOTIATE": "negotiate",
                "AUTOMATE": "automate",
            },
        ),
        "savings_confidence": EnumDef(
            "SavingsConfidence",
            {
                "CONFIRMED": "confirmed",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "SPECULATIVE": "speculative",
            },
        ),
    },
)

# Backward-compatible re-exports
EfficiencyDomain = PlatformEfficiencyOptimizer.EfficiencyDomain
OptimizationAction = PlatformEfficiencyOptimizer.OptimizationAction
SavingsConfidence = PlatformEfficiencyOptimizer.SavingsConfidence
PlatformEfficiencyOptimizerRecord = PlatformEfficiencyOptimizer.Record
PlatformEfficiencyOptimizerAnalysis = PlatformEfficiencyOptimizer.Analysis
PlatformEfficiencyOptimizerReport = PlatformEfficiencyOptimizer.Report
