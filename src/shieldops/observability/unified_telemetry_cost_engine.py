"""UnifiedTelemetryCostEngine — Track unified telemetry costs across signals."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

UnifiedTelemetryCostEngine = engine(
    "UnifiedTelemetryCostEngine",
    description="Track unified telemetry costs across all three signals.",
    enums={
        "signal": EnumDef(
            "TelemetrySignal",
            {
                "TRACES": "traces",
                "METRICS": "metrics",
                "LOGS": "logs",
            },
        ),
        "driver": EnumDef(
            "CostDriver",
            {
                "VOLUME": "volume",
                "CARDINALITY": "cardinality",
                "RETENTION": "retention",
                "EGRESS": "egress",
            },
        ),
        "trend": EnumDef(
            "CostTrend",
            {
                "INCREASING": "increasing",
                "STABLE": "stable",
                "DECREASING": "decreasing",
            },
        ),
    },
    record_fields=[
        FieldDef("cost_usd", float, 0.0),
        FieldDef("volume_gb", float, 0.0),
    ],
)

# Backward-compatible re-exports
TelemetrySignal = UnifiedTelemetryCostEngine.TelemetrySignal
CostDriver = UnifiedTelemetryCostEngine.CostDriver
CostTrend = UnifiedTelemetryCostEngine.CostTrend
UnifiedTelemetryCostRecord = UnifiedTelemetryCostEngine.Record
UnifiedTelemetryCostAnalysis = UnifiedTelemetryCostEngine.Analysis
UnifiedTelemetryCostReport = UnifiedTelemetryCostEngine.Report
