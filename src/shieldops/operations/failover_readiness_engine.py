"""Failover Readiness Engine — track failover readiness across services."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

FailoverReadinessEngine = engine(
    "FailoverReadinessEngine",
    description="Track failover readiness across services and components.",
    enums={
        "readiness_level": EnumDef(
            "ReadinessLevel",
            {
                "READY": "ready",
                "PARTIALLY_READY": "partially_ready",
                "NOT_READY": "not_ready",
                "UNTESTED": "untested",
                "DEGRADED": "degraded",
            },
        ),
        "failover_component": EnumDef(
            "FailoverComponent",
            {
                "DATABASE": "database",
                "APPLICATION": "application",
                "LOADBALANCER": "loadbalancer",
                "DNS": "dns",
                "STORAGE": "storage",
            },
        ),
        "validation_frequency": EnumDef(
            "ValidationFrequency",
            {
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
                "QUARTERLY": "quarterly",
                "ANNUAL": "annual",
            },
        ),
    },
    record_fields=[
        FieldDef("last_validated_at", float, 0.0),
        FieldDef("failover_time_seconds", float, 0.0),
        FieldDef("target_failover_seconds", float, 0.0),
        FieldDef("replication_lag_ms", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="service_id",
)

# Backward-compatible re-exports
ReadinessLevel = FailoverReadinessEngine.ReadinessLevel
FailoverComponent = FailoverReadinessEngine.FailoverComponent
ValidationFrequency = FailoverReadinessEngine.ValidationFrequency
FailoverReadinessRecord = FailoverReadinessEngine.Record
FailoverReadinessAnalysis = FailoverReadinessEngine.Analysis
FailoverReadinessReport = FailoverReadinessEngine.Report
