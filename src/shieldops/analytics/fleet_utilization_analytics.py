"""Fleet Utilization Analytics — measure and forecast fleet usage."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

FleetUtilizationAnalytics = engine(
    "FleetUtilizationAnalytics",
    description="Measure fleet utilization and cost efficiency.",
    enums={
        "metric": EnumDef(
            "UtilizationMetric",
            {
                "CPU": "cpu",
                "MEMORY": "memory",
                "NETWORK": "network",
                "DISK": "disk",
                "GPU": "gpu",
            },
        ),
        "efficiency": EnumDef(
            "CostEfficiency",
            {
                "OPTIMAL": "optimal",
                "ACCEPTABLE": "acceptable",
                "WASTEFUL": "wasteful",
                "CRITICAL": "critical",
            },
        ),
        "forecast": EnumDef(
            "CapacityForecast",
            {
                "UNDER_CAPACITY": "under_capacity",
                "ADEQUATE": "adequate",
                "NEARING_LIMIT": "nearing_limit",
                "EXCEEDED": "exceeded",
            },
        ),
    },
    key_field="agent_name",
)

# Backward-compatible re-exports
UtilizationMetric = FleetUtilizationAnalytics.UtilizationMetric
CostEfficiency = FleetUtilizationAnalytics.CostEfficiency
CapacityForecast = FleetUtilizationAnalytics.CapacityForecast
UtilizationRecord = FleetUtilizationAnalytics.Record
UtilizationAnalysis = FleetUtilizationAnalytics.Analysis
UtilizationReport = FleetUtilizationAnalytics.Report
