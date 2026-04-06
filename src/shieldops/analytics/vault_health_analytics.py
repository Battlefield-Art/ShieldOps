"""Vault Health Analytics — track health, capacity, and recovery readiness."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

VaultHealthAnalytics = engine(
    "VaultHealthAnalytics",
    description="Track vault health, forecast capacity, and measure recovery.",
    enums={
        "metric": EnumDef(
            "VaultMetric",
            {
                "INTEGRITY_CHECK": "integrity_check",
                "ACCESS_LATENCY": "access_latency",
                "STORAGE_USAGE": "storage_usage",
                "REPLICATION_LAG": "replication_lag",
                "SEAL_STATUS": "seal_status",
            },
        ),
        "health_trend": EnumDef(
            "HealthTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DEGRADING": "degrading",
                "CRITICAL": "critical",
                "UNKNOWN": "unknown",
            },
        ),
        "capacity_forecast": EnumDef(
            "CapacityForecast",
            {
                "SUFFICIENT": "sufficient",
                "ADEQUATE": "adequate",
                "APPROACHING_LIMIT": "approaching_limit",
                "NEAR_CAPACITY": "near_capacity",
                "EXCEEDED": "exceeded",
            },
        ),
    },
    record_fields=[
        FieldDef("value", float, 0.0),
        FieldDef("storage_used_pct", float, 0.0),
        FieldDef("replication_lag_ms", float, 0.0),
        FieldDef("recovery_time_objective_hours", float, 4.0),
    ],
    key_field="vault_id",
)

# Backward-compatible re-exports
VaultMetric = VaultHealthAnalytics.VaultMetric
HealthTrend = VaultHealthAnalytics.HealthTrend
CapacityForecast = VaultHealthAnalytics.CapacityForecast
VaultHealthRecord = VaultHealthAnalytics.Record
VaultHealthAnalysis = VaultHealthAnalytics.Analysis
VaultHealthReport = VaultHealthAnalytics.Report
