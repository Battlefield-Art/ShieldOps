"""Service Mesh Capacity Forecaster. Forecast proxy resource needs, model mesh scaling scenari..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ServiceMeshCapacityForecaster = engine(
    "ServiceMeshCapacityForecaster",
    description="Forecast proxy resource needs, model scaling scenarios, detect capacity bot...",
    enums={
        "resource_type": EnumDef(
            "ResourceType",
            {
                "CPU": "cpu",
                "MEMORY": "memory",
                "CONNECTIONS": "connections",
                "BANDWIDTH": "bandwidth",
            },
        ),
        "scaling_trigger": EnumDef(
            "ScalingTrigger",
            {
                "TRAFFIC_GROWTH": "traffic_growth",
                "NEW_SERVICES": "new_services",
                "MESH_EXPANSION": "mesh_expansion",
                "PERFORMANCE": "performance",
            },
        ),
        "bottleneck_severity": EnumDef(
            "BottleneckSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("current_usage", float, 0.0),
        FieldDef("capacity_limit", float, 100.0),
        FieldDef("utilization_pct", float, 0.0),
    ],
    key_field="proxy_name",
)

# Backward-compatible re-exports
ResourceType = ServiceMeshCapacityForecaster.ResourceType
ScalingTrigger = ServiceMeshCapacityForecaster.ScalingTrigger
BottleneckSeverity = ServiceMeshCapacityForecaster.BottleneckSeverity
MeshCapacityRecord = ServiceMeshCapacityForecaster.Record
MeshCapacityAnalysis = ServiceMeshCapacityForecaster.Analysis
MeshCapacityReport = ServiceMeshCapacityForecaster.Report
