"""Collector Fleet Autoscaler Engine — compute scaling decisions, detect collector hotspots, f..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CollectorFleetAutoscalerEngine = engine(
    "CollectorFleetAutoscalerEngine",
    description="Compute scaling decisions, detect collector hotspots, forecast fleet capacity.",
    enums={
        "scaling_trigger": EnumDef(
            "ScalingTrigger",
            {
                "CPU_PRESSURE": "cpu_pressure",
                "MEMORY_PRESSURE": "memory_pressure",
                "QUEUE_DEPTH": "queue_depth",
                "THROUGHPUT_LAG": "throughput_lag",
            },
        ),
        "scaling_action": EnumDef(
            "ScalingAction",
            {
                "SCALE_UP": "scale_up",
                "SCALE_DOWN": "scale_down",
                "REBALANCE": "rebalance",
                "NO_ACTION": "no_action",
            },
        ),
        "fleet_health": EnumDef(
            "FleetHealth",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "OVERLOADED": "overloaded",
                "UNDERUTILIZED": "underutilized",
            },
        ),
    },
    record_fields=[
        FieldDef("cpu_utilization", float, 0.0),
        FieldDef("memory_utilization", float, 0.0),
        FieldDef("queue_depth", int, 0),
        FieldDef("throughput_lag_sec", float, 0.0),
        FieldDef("replica_count", int, 1),
        FieldDef("description", str, ""),
    ],
    key_field="collector_id",
)

# Backward-compatible re-exports
ScalingTrigger = CollectorFleetAutoscalerEngine.ScalingTrigger
ScalingAction = CollectorFleetAutoscalerEngine.ScalingAction
FleetHealth = CollectorFleetAutoscalerEngine.FleetHealth
CollectorFleetRecord = CollectorFleetAutoscalerEngine.Record
CollectorFleetAnalysis = CollectorFleetAutoscalerEngine.Analysis
CollectorFleetReport = CollectorFleetAutoscalerEngine.Report
