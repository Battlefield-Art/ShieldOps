"""ResourceOptimizationIntelligence — resource optimization intelligence."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ResourceOptimizationIntelligence = engine(
    "ResourceOptimizationIntelligence",
    module="operations",  # uses record_item
    description="Resource Optimization Intelligence.",
    enums={
        "optimization_type": EnumDef(
            "OptimizationType",
            {
                "RIGHTSIZING": "rightsizing",
                "SCHEDULING": "scheduling",
                "CONSOLIDATION": "consolidation",
                "MIGRATION": "migration",
                "ELIMINATION": "elimination",
            },
        ),
        "savings_potential": EnumDef(
            "SavingsPotential",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "MINIMAL": "minimal",
                "NEGATIVE": "negative",
            },
        ),
        "implementation_risk": EnumDef(
            "ImplementationRisk",
            {
                "LOW": "low",
                "MEDIUM": "medium",
                "HIGH": "high",
                "VERY_HIGH": "very_high",
                "CRITICAL": "critical",
            },
        ),
    },
)

# Backward-compatible re-exports
OptimizationType = ResourceOptimizationIntelligence.OptimizationType
SavingsPotential = ResourceOptimizationIntelligence.SavingsPotential
ImplementationRisk = ResourceOptimizationIntelligence.ImplementationRisk
ResourceOptimizationIntelligenceRecord = ResourceOptimizationIntelligence.Record
ResourceOptimizationIntelligenceAnalysis = ResourceOptimizationIntelligence.Analysis
ResourceOptimizationIntelligenceReport = ResourceOptimizationIntelligence.Report
