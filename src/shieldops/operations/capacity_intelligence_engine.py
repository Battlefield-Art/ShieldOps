"""CapacityIntelligenceEngine Predictive capacity planning, resource right-sizing, scaling rec..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CapacityIntelligenceEngine = engine(
    "CapacityIntelligenceEngine",
    module="operations",  # uses record_item
    description="Predictive capacity planning with resource right-sizing and cost-aware prov...",
    enums={
        "resource_type": EnumDef(
            "ResourceType",
            {
                "CPU": "cpu",
                "MEMORY": "memory",
                "DISK": "disk",
                "NETWORK": "network",
                "GPU": "gpu",
            },
        ),
        "sizing_action": EnumDef(
            "SizingAction",
            {
                "UPSIZE": "upsize",
                "DOWNSIZE": "downsize",
                "MAINTAIN": "maintain",
                "CONSOLIDATE": "consolidate",
                "DECOMMISSION": "decommission",
            },
        ),
        "capacity_risk": EnumDef(
            "CapacityRisk",
            {
                "EXHAUSTION_IMMINENT": "exhaustion_imminent",
                "APPROACHING_LIMIT": "approaching_limit",
                "HEALTHY": "healthy",
                "OVER_PROVISIONED": "over_provisioned",
                "IDLE": "idle",
            },
        ),
    },
    record_fields=[
        FieldDef("current_utilization_pct", float, 0.0),
        FieldDef("peak_utilization_pct", float, 0.0),
        FieldDef("allocated_units", float, 0.0),
        FieldDef("used_units", float, 0.0),
        FieldDef("projected_exhaustion_days", int, 0),
        FieldDef("monthly_cost", float, 0.0),
        FieldDef("potential_savings", float, 0.0),
    ],
)

# Backward-compatible re-exports
ResourceType = CapacityIntelligenceEngine.ResourceType
SizingAction = CapacityIntelligenceEngine.SizingAction
CapacityRisk = CapacityIntelligenceEngine.CapacityRisk
CapacityIntelligenceRecord = CapacityIntelligenceEngine.Record
CapacityIntelligenceAnalysis = CapacityIntelligenceEngine.Analysis
CapacityIntelligenceReport = CapacityIntelligenceEngine.Report
