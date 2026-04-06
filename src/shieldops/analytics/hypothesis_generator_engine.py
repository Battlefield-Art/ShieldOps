"""Hypothesis Generator Engine Generate, rank, and prune optimization hypotheses based on metr..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

HypothesisGeneratorEngine = engine(
    "HypothesisGeneratorEngine",
    description="Generate, rank, and prune optimization hypotheses from metric and failure a...",
    enums={
        "source": EnumDef(
            "HypothesisSource",
            {
                "METRIC_ANALYSIS": "metric_analysis",
                "FAILURE_PATTERN": "failure_pattern",
                "PEER_COMPARISON": "peer_comparison",
                "RANDOM_EXPLORATION": "random_exploration",
            },
        ),
        "confidence": EnumDef(
            "HypothesisConfidence",
            {
                "STRONG": "strong",
                "MODERATE": "moderate",
                "WEAK": "weak",
                "SPECULATIVE": "speculative",
            },
        ),
        "validation": EnumDef(
            "ValidationMethod",
            {
                "AB_TEST": "ab_test",
                "HOLDOUT": "holdout",
                "CROSS_VALIDATION": "cross_validation",
                "BOOTSTRAP": "bootstrap",
            },
        ),
    },
    record_fields=[
        FieldDef("hypothesis_name", str, ""),
        FieldDef("expected_impact", float, 0.0),
        FieldDef("tested", bool, False),
    ],
    key_field="agent_id",
)

# Backward-compatible re-exports
HypothesisSource = HypothesisGeneratorEngine.HypothesisSource
HypothesisConfidence = HypothesisGeneratorEngine.HypothesisConfidence
ValidationMethod = HypothesisGeneratorEngine.ValidationMethod
HypothesisRecord = HypothesisGeneratorEngine.Record
HypothesisAnalysis = HypothesisGeneratorEngine.Analysis
HypothesisReport = HypothesisGeneratorEngine.Report
