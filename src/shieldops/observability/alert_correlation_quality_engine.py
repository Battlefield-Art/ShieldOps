"""AlertCorrelationQualityEngine — Track and analyze alert correlation quality."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AlertCorrelationQualityEngine = engine(
    "AlertCorrelationQualityEngine",
    description="Track and analyze alert correlation quality and noise reduction.",
    enums={
        "correlation_method": EnumDef(
            "CorrelationMethod",
            {
                "TEMPORAL": "temporal",
                "CAUSAL": "causal",
                "GRAPH": "graph",
                "ML_CLUSTER": "ml_cluster",
                "RULE_BASED": "rule_based",
            },
        ),
        "correlation_accuracy": EnumDef(
            "CorrelationAccuracy",
            {
                "TRUE_POSITIVE": "true_positive",
                "FALSE_POSITIVE": "false_positive",
                "TRUE_NEGATIVE": "true_negative",
                "FALSE_NEGATIVE": "false_negative",
                "UNVERIFIED": "unverified",
            },
        ),
        "noise_reduction": EnumDef(
            "NoiseReduction",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "MODERATE": "moderate",
                "POOR": "poor",
                "NONE": "none",
            },
        ),
    },
    record_fields=[
        FieldDef("alerts_correlated", int, 0),
        FieldDef("correlation_time_ms", float, 0.0),
    ],
)

# Backward-compatible re-exports
CorrelationMethod = AlertCorrelationQualityEngine.CorrelationMethod
CorrelationAccuracy = AlertCorrelationQualityEngine.CorrelationAccuracy
NoiseReduction = AlertCorrelationQualityEngine.NoiseReduction
AlertCorrelationQualityRecord = AlertCorrelationQualityEngine.Record
AlertCorrelationQualityAnalysis = AlertCorrelationQualityEngine.Analysis
AlertCorrelationQualityReport = AlertCorrelationQualityEngine.Report
