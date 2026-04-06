"""ProactiveCapacityEngine — proactive capacity engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ProactiveCapacityEngine = engine(
    "ProactiveCapacityEngine",
    module="operations",  # uses record_item
    description="Proactive Capacity Engine.",
    enums={
        "resource_type": EnumDef(
            "ResourceType",
            {
                "CPU": "cpu",
                "MEMORY": "memory",
                "STORAGE": "storage",
                "NETWORK": "network",
                "GPU": "gpu",
            },
        ),
        "capacity_action": EnumDef(
            "CapacityAction",
            {
                "SCALE_UP": "scale_up",
                "SCALE_OUT": "scale_out",
                "OPTIMIZE": "optimize",
                "MIGRATE": "migrate",
                "RESERVE": "reserve",
            },
        ),
        "forecast_accuracy": EnumDef(
            "ForecastAccuracy",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
                "UNRELIABLE": "unreliable",
            },
        ),
    },
)

# Backward-compatible re-exports
ResourceType = ProactiveCapacityEngine.ResourceType
CapacityAction = ProactiveCapacityEngine.CapacityAction
ForecastAccuracy = ProactiveCapacityEngine.ForecastAccuracy
ProactiveCapacityEngineRecord = ProactiveCapacityEngine.Record
ProactiveCapacityEngineAnalysis = ProactiveCapacityEngine.Analysis
ProactiveCapacityEngineReport = ProactiveCapacityEngine.Report
