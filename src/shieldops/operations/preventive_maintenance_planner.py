"""PreventiveMaintenancePlanner — preventive maintenance planner."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PreventiveMaintenancePlanner = engine(
    "PreventiveMaintenancePlanner",
    module="operations",  # uses record_item
    description="Preventive Maintenance Planner.",
    enums={
        "maintenance_type": EnumDef(
            "MaintenanceType",
            {
                "PATCHING": "patching",
                "UPGRADE": "upgrade",
                "REPLACEMENT": "replacement",
                "OPTIMIZATION": "optimization",
                "CERTIFICATION": "certification",
            },
        ),
        "maintenance_window": EnumDef(
            "MaintenanceWindow",
            {
                "IMMEDIATE": "immediate",
                "NEXT_WINDOW": "next_window",
                "SCHEDULED": "scheduled",
                "DEFERRED": "deferred",
                "ON_DEMAND": "on_demand",
            },
        ),
        "maintenance_risk": EnumDef(
            "MaintenanceRisk",
            {
                "LOW": "low",
                "MEDIUM": "medium",
                "HIGH": "high",
                "VERY_HIGH": "very_high",
                "CRITICAL": "critical",
            },
        ),
    },
)

# Backward-compatible re-exports
MaintenanceType = PreventiveMaintenancePlanner.MaintenanceType
MaintenanceWindow = PreventiveMaintenancePlanner.MaintenanceWindow
MaintenanceRisk = PreventiveMaintenancePlanner.MaintenanceRisk
PreventiveMaintenancePlannerRecord = PreventiveMaintenancePlanner.Record
PreventiveMaintenancePlannerAnalysis = PreventiveMaintenancePlanner.Analysis
PreventiveMaintenancePlannerReport = PreventiveMaintenancePlanner.Report
