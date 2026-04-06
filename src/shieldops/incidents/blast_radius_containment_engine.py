"""Blast Radius Containment Engine — compute containment effectiveness, detect blast radius ex..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

BlastRadiusContainmentEngine = engine(
    "BlastRadiusContainmentEngine",
    description="Compute containment effectiveness, detect blast radius expansion, rank inci...",
    enums={
        "containment_status": EnumDef(
            "ContainmentStatus",
            {
                "CONTAINED": "contained",
                "SPREADING": "spreading",
                "ISOLATED": "isolated",
                "UNKNOWN": "unknown",
            },
        ),
        "blast_level": EnumDef(
            "BlastLevel",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "containment_strategy": EnumDef(
            "ContainmentStrategy",
            {
                "NETWORK_ISOLATION": "network_isolation",
                "SERVICE_SHUTDOWN": "service_shutdown",
                "TRAFFIC_DIVERT": "traffic_divert",
                "RATE_LIMIT": "rate_limit",
            },
        ),
    },
    record_fields=[
        FieldDef("affected_services", int, 0),
        FieldDef("containment_time_seconds", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="incident_id",
)

# Backward-compatible re-exports
ContainmentStatus = BlastRadiusContainmentEngine.ContainmentStatus
BlastLevel = BlastRadiusContainmentEngine.BlastLevel
ContainmentStrategy = BlastRadiusContainmentEngine.ContainmentStrategy
BlastRadiusRecord = BlastRadiusContainmentEngine.Record
BlastRadiusAnalysis = BlastRadiusContainmentEngine.Analysis
BlastRadiusReport = BlastRadiusContainmentEngine.Report
