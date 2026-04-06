"""CardinalityControlEngine — monitor and control metric cardinality."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CardinalityControlEngine = engine(
    "CardinalityControlEngine",
    description="Cardinality Control Engine — detect label explosions and enforce limits.",
    enums={
        "cardinality_level": EnumDef(
            "CardinalityLevel",
            {
                "NORMAL": "normal",
                "ELEVATED": "elevated",
                "HIGH": "high",
                "EXPLOSIVE": "explosive",
            },
        ),
        "control_action": EnumDef(
            "ControlAction",
            {
                "AGGREGATE": "aggregate",
                "DROP_LABEL": "drop_label",
                "RATE_LIMIT": "rate_limit",
                "ALLOWLIST": "allowlist",
            },
        ),
        "metric_type": EnumDef(
            "MetricType",
            {
                "COUNTER": "counter",
                "GAUGE": "gauge",
                "HISTOGRAM": "histogram",
                "SUMMARY": "summary",
            },
        ),
    },
    record_fields=[
        FieldDef("label_count", int, 0),
        FieldDef("series_count", int, 0),
        FieldDef("growth_rate_pct", float, 0.0),
    ],
)

# Backward-compatible re-exports
CardinalityLevel = CardinalityControlEngine.CardinalityLevel
ControlAction = CardinalityControlEngine.ControlAction
MetricType = CardinalityControlEngine.MetricType
CardinalityControlRecord = CardinalityControlEngine.Record
CardinalityControlAnalysis = CardinalityControlEngine.Analysis
CardinalityControlReport = CardinalityControlEngine.Report
