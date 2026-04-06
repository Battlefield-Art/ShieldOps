"""TelemetryCostAttributionEngine — telemetry cost attribution engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

TelemetryCostAttributionEngine = engine(
    "TelemetryCostAttributionEngine",
    module="operations",  # uses record_item
    description="Telemetry Cost Attribution Engine.",
    enums={
        "cost_category": EnumDef(
            "CostCategory",
            {
                "INGESTION": "ingestion",
                "STORAGE": "storage",
                "QUERY": "query",
                "EXPORT": "export",
                "PROCESSING": "processing",
            },
        ),
        "attribution_model": EnumDef(
            "AttributionModel",
            {
                "DIRECT": "direct",
                "PROPORTIONAL": "proportional",
                "ACTIVITY_BASED": "activity_based",
                "TIERED": "tiered",
                "BLENDED": "blended",
            },
        ),
        "cost_trend": EnumDef(
            "CostTrend",
            {
                "INCREASING": "increasing",
                "STABLE": "stable",
                "DECREASING": "decreasing",
                "VOLATILE": "volatile",
                "OPTIMIZING": "optimizing",
            },
        ),
    },
)

# Backward-compatible re-exports
CostCategory = TelemetryCostAttributionEngine.CostCategory
AttributionModel = TelemetryCostAttributionEngine.AttributionModel
CostTrend = TelemetryCostAttributionEngine.CostTrend
TelemetryCostAttributionEngineRecord = TelemetryCostAttributionEngine.Record
TelemetryCostAttributionEngineAnalysis = TelemetryCostAttributionEngine.Analysis
TelemetryCostAttributionEngineReport = TelemetryCostAttributionEngine.Report
