"""Telemetry Fanout Router Engine — evaluate fanout efficiency, detect routing asymmetry, opti..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TelemetryFanoutRouterEngine = engine(
    "TelemetryFanoutRouterEngine",
    description="Evaluate fanout efficiency, detect routing asymmetry, optimize routing rules.",
    enums={
        "routing_strategy": EnumDef(
            "RoutingStrategy",
            {
                "BROADCAST": "broadcast",
                "CONTENT_BASED": "content_based",
                "ROUND_ROBIN": "round_robin",
                "PRIORITY_BASED": "priority_based",
            },
        ),
        "fanout_status": EnumDef(
            "FanoutStatus",
            {
                "ALL_DELIVERED": "all_delivered",
                "PARTIAL_DELIVERY": "partial_delivery",
                "PRIMARY_ONLY": "primary_only",
                "ALL_FAILED": "all_failed",
            },
        ),
        "routing_criteria": EnumDef(
            "RoutingCriteria",
            {
                "SIGNAL_TYPE": "signal_type",
                "SERVICE_NAME": "service_name",
                "ENVIRONMENT": "environment",
                "PRIORITY_LEVEL": "priority_level",
            },
        ),
    },
    record_fields=[
        FieldDef("destination_count", int, 1),
        FieldDef("delivered_count", int, 0),
        FieldDef("items_routed", int, 0),
        FieldDef("routing_latency_ms", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="asymmetry_score",
    key_field="route_id",
)

# Backward-compatible re-exports
RoutingStrategy = TelemetryFanoutRouterEngine.RoutingStrategy
FanoutStatus = TelemetryFanoutRouterEngine.FanoutStatus
RoutingCriteria = TelemetryFanoutRouterEngine.RoutingCriteria
TelemetryFanoutRecord = TelemetryFanoutRouterEngine.Record
TelemetryFanoutAnalysis = TelemetryFanoutRouterEngine.Analysis
TelemetryFanoutReport = TelemetryFanoutRouterEngine.Report
