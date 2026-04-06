"""Predictive Maintenance Planner V2 — predictive maintenance with ML-driven scheduling."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PredictiveMaintenancePlannerV2 = engine(
    "PredictiveMaintenancePlannerV2",
    module="operations",  # uses record_item
    description="Predictive Maintenance Planner V2 for ML-driven maintenance scheduling.",
    enums={
        "maintenance_type": EnumDef(
            "MaintenanceType",
            {
                "PREVENTIVE": "preventive",
                "PREDICTIVE": "predictive",
                "CORRECTIVE": "corrective",
                "EMERGENCY": "emergency",
            },
        ),
        "component_health": EnumDef(
            "ComponentHealth",
            {
                "HEALTHY": "healthy",
                "DEGRADING": "degrading",
                "FAILING": "failing",
                "FAILED": "failed",
            },
        ),
        "maintenance_window": EnumDef(
            "MaintenanceWindow",
            {
                "IMMEDIATE": "immediate",
                "NEXT_WINDOW": "next_window",
                "SCHEDULED": "scheduled",
                "DEFERRED": "deferred",
            },
        ),
    },
)

# Backward-compatible re-exports
MaintenanceType = PredictiveMaintenancePlannerV2.MaintenanceType
ComponentHealth = PredictiveMaintenancePlannerV2.ComponentHealth
MaintenanceWindow = PredictiveMaintenancePlannerV2.MaintenanceWindow
MaintenanceRecord = PredictiveMaintenancePlannerV2.Record
MaintenanceAnalysis = PredictiveMaintenancePlannerV2.Analysis
PredictiveMaintenanceReport = PredictiveMaintenancePlannerV2.Report
