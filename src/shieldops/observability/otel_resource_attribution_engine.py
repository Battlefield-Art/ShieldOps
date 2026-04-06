"""OTelResourceAttributionEngine — attribute telemetry costs (storage, processing, export) to..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OTelResourceAttributionEngine = engine(
    "OTelResourceAttributionEngine",
    description="Attribute telemetry costs to individual services and teams.",
    enums={
        "resource_cost_type": EnumDef(
            "ResourceCostType",
            {
                "STORAGE": "storage",
                "PROCESSING": "processing",
                "EXPORT": "export",
                "INGESTION": "ingestion",
            },
        ),
        "attribution_method": EnumDef(
            "AttributionMethod",
            {
                "PROPORTIONAL": "proportional",
                "FIXED_ALLOCATION": "fixed_allocation",
                "USAGE_BASED": "usage_based",
                "TIERED": "tiered",
            },
        ),
        "cost_trend": EnumDef(
            "CostTrend",
            {
                "INCREASING": "increasing",
                "STABLE": "stable",
                "DECREASING": "decreasing",
                "ANOMALOUS": "anomalous",
            },
        ),
    },
    record_fields=[
        FieldDef("cost_usd", float, 0.0),
        FieldDef("volume_bytes", float, 0.0),
    ],
    key_field="service_name",
)

# Backward-compatible re-exports
ResourceCostType = OTelResourceAttributionEngine.ResourceCostType
AttributionMethod = OTelResourceAttributionEngine.AttributionMethod
CostTrend = OTelResourceAttributionEngine.CostTrend
ResourceAttributionRecord = OTelResourceAttributionEngine.Record
ResourceAttributionAnalysis = OTelResourceAttributionEngine.Analysis
ResourceAttributionReport = OTelResourceAttributionEngine.Report
