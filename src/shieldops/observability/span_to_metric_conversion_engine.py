"""Span to Metric Conversion Engine — evaluate conversion accuracy, detect cardinality explosi..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SpanToMetricConversionEngine = engine(
    "SpanToMetricConversionEngine",
    description="Evaluate conversion accuracy, detect cardinality explosion, optimize conver...",
    enums={
        "conversion_type": EnumDef(
            "ConversionType",
            {
                "REQUEST_RATE": "request_rate",
                "ERROR_RATE": "error_rate",
                "DURATION_HISTOGRAM": "duration_histogram",
                "CUSTOM_AGGREGATE": "custom_aggregate",
            },
        ),
        "cardinality_risk": EnumDef(
            "CardinalityRisk",
            {
                "SAFE": "safe",
                "ELEVATED": "elevated",
                "HIGH": "high",
                "EXPLOSIVE": "explosive",
            },
        ),
        "metric_granularity": EnumDef(
            "MetricGranularity",
            {
                "SERVICE_LEVEL": "service_level",
                "ENDPOINT_LEVEL": "endpoint_level",
                "OPERATION_LEVEL": "operation_level",
                "ATTRIBUTE_LEVEL": "attribute_level",
            },
        ),
    },
    record_fields=[
        FieldDef("spans_per_sec", float, 0.0),
        FieldDef("metrics_produced", int, 0),
        FieldDef("unique_label_sets", int, 0),
        FieldDef("accuracy_pct", float, 100.0),
        FieldDef("description", str, ""),
    ],
    key_field="rule_id",
)

# Backward-compatible re-exports
ConversionType = SpanToMetricConversionEngine.ConversionType
CardinalityRisk = SpanToMetricConversionEngine.CardinalityRisk
MetricGranularity = SpanToMetricConversionEngine.MetricGranularity
SpanToMetricRecord = SpanToMetricConversionEngine.Record
SpanToMetricAnalysis = SpanToMetricConversionEngine.Analysis
SpanToMetricReport = SpanToMetricConversionEngine.Report
