"""Operational Complexity Scorer — complexity scoring and simplification."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

OperationalComplexityScorer = engine(
    "OperationalComplexityScorer",
    description="Operational Complexity Scorer for complexity scoring and simplification.",
    enums={
        "complexity_dimension": EnumDef(
            "ComplexityDimension",
            {
                "ARCHITECTURAL": "architectural",
                "OPERATIONAL": "operational",
                "ORGANIZATIONAL": "organizational",
                "TECHNICAL": "technical",
            },
        ),
        "complexity_driver": EnumDef(
            "ComplexityDriver",
            {
                "DEPENDENCIES": "dependencies",
                "SCALE": "scale",
                "HETEROGENEITY": "heterogeneity",
                "CHANGE_RATE": "change_rate",
            },
        ),
        "risk_impact": EnumDef(
            "RiskImpact",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
            },
        ),
    },
)

# Backward-compatible re-exports
ComplexityDimension = OperationalComplexityScorer.ComplexityDimension
ComplexityDriver = OperationalComplexityScorer.ComplexityDriver
RiskImpact = OperationalComplexityScorer.RiskImpact
ComplexityRecord = OperationalComplexityScorer.Record
ComplexityAnalysis = OperationalComplexityScorer.Analysis
OperationalComplexityReport = OperationalComplexityScorer.Report
