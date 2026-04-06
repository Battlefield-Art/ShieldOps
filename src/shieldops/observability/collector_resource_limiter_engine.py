"""Collector Resource Limiter Engine — predict OOM risk, evaluate limit headroom, recommend re..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CollectorResourceLimiterEngine = engine(
    "CollectorResourceLimiterEngine",
    description="Predict OOM risk, evaluate limit headroom, recommend resource allocation.",
    enums={
        "resource_type": EnumDef(
            "ResourceType",
            {
                "MEMORY_RSS": "memory_rss",
                "CPU_CORES": "cpu_cores",
                "DISK_BUFFER": "disk_buffer",
                "NETWORK_BANDWIDTH": "network_bandwidth",
            },
        ),
        "limit_status": EnumDef(
            "LimitStatus",
            {
                "WITHIN_BUDGET": "within_budget",
                "APPROACHING_LIMIT": "approaching_limit",
                "AT_LIMIT": "at_limit",
                "EXCEEDED": "exceeded",
            },
        ),
        "mitigation_action": EnumDef(
            "MitigationAction",
            {
                "INCREASE_SAMPLING": "increase_sampling",
                "DROP_LOW_PRIORITY": "drop_low_priority",
                "FLUSH_BUFFER": "flush_buffer",
                "RESTART_COLLECTOR": "restart_collector",
            },
        ),
    },
    record_fields=[
        FieldDef("current_usage", float, 0.0),
        FieldDef("limit_value", float, 0.0),
        FieldDef("usage_trend_pct_per_hour", float, 0.0),
        FieldDef("restart_count", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="collector_id",
)

# Backward-compatible re-exports
ResourceType = CollectorResourceLimiterEngine.ResourceType
LimitStatus = CollectorResourceLimiterEngine.LimitStatus
MitigationAction = CollectorResourceLimiterEngine.MitigationAction
CollectorResourceRecord = CollectorResourceLimiterEngine.Record
CollectorResourceAnalysis = CollectorResourceLimiterEngine.Analysis
CollectorResourceReport = CollectorResourceLimiterEngine.Report
