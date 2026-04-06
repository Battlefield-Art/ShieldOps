"""TelemetryCostAttribution — telemetry cost attribution."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

TelemetryCostAttribution = engine(
    "TelemetryCostAttribution",
    description="Telemetry cost attribution engine.",
    enums={
        "cost_driver": EnumDef(
            "CostDriver",
            {
                "INGESTION_VOLUME": "ingestion_volume",
                "CARDINALITY": "cardinality",
                "QUERY_RATE": "query_rate",
                "RETENTION": "retention",
            },
        ),
        "attribution_method": EnumDef(
            "AttributionMethod",
            {
                "PROPORTIONAL": "proportional",
                "DIRECT": "direct",
                "ACTIVITY_BASED": "activity_based",
                "HYBRID": "hybrid",
            },
        ),
        "cost_trend": EnumDef(
            "CostTrend",
            {
                "INCREASING": "increasing",
                "STABLE": "stable",
                "DECREASING": "decreasing",
                "SPIKE": "spike",
            },
        ),
    },
)

# Backward-compatible re-exports
CostDriver = TelemetryCostAttribution.CostDriver
AttributionMethod = TelemetryCostAttribution.AttributionMethod
CostTrend = TelemetryCostAttribution.CostTrend
TelemetryCostAttributionRecord = TelemetryCostAttribution.Record
TelemetryCostAttributionAnalysis = TelemetryCostAttribution.Analysis
TelemetryCostAttributionReport = TelemetryCostAttribution.Report
