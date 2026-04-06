"""OtelConnectorRoutingEngine — route telemetry between pipelines via OTel connectors."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OtelConnectorRoutingEngine = engine(
    "OtelConnectorRoutingEngine",
    description="Route telemetry between pipelines via OTel connectors.",
    enums={
        "connector_type": EnumDef(
            "ConnectorType",
            {
                "COUNT": "count",
                "SPANMETRICS": "spanmetrics",
                "FORWARD": "forward",
                "ROUTING": "routing",
            },
        ),
        "routing_strategy": EnumDef(
            "RoutingStrategy",
            {
                "ROUND_ROBIN": "round_robin",
                "CONTENT_BASED": "content_based",
                "PRIORITY": "priority",
            },
        ),
        "routing_health": EnumDef(
            "RoutingHealth",
            {
                "OPTIMAL": "optimal",
                "SUBOPTIMAL": "suboptimal",
                "BROKEN": "broken",
            },
        ),
    },
    record_fields=[
        FieldDef("route_count", int, 0),
        FieldDef("latency_ms", float, 0.0),
    ],
)

# Backward-compatible re-exports
ConnectorType = OtelConnectorRoutingEngine.ConnectorType
RoutingStrategy = OtelConnectorRoutingEngine.RoutingStrategy
RoutingHealth = OtelConnectorRoutingEngine.RoutingHealth
OtelConnectorRoutingRecord = OtelConnectorRoutingEngine.Record
OtelConnectorRoutingAnalysis = OtelConnectorRoutingEngine.Analysis
OtelConnectorRoutingReport = OtelConnectorRoutingEngine.Report
