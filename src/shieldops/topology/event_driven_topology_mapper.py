"""Event Driven Topology Mapper — map event flow paths, detect circular flows, rank services b..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EventDrivenTopologyMapper = engine(
    "EventDrivenTopologyMapper",
    module="operations",  # uses record_item
    description="Map event flow paths, detect circular flows, rank services by event central...",
    enums={
        "flow_pattern": EnumDef(
            "FlowPattern",
            {
                "POINT_TO_POINT": "point_to_point",
                "FANOUT": "fanout",
                "FANIN": "fanin",
                "PIPELINE": "pipeline",
            },
        ),
        "topology_role": EnumDef(
            "TopologyRole",
            {
                "PRODUCER": "producer",
                "CONSUMER": "consumer",
                "PROCESSOR": "processor",
                "ROUTER": "router",
            },
        ),
        "centrality_level": EnumDef(
            "CentralityLevel",
            {
                "HUB": "hub",
                "SIGNIFICANT": "significant",
                "PERIPHERAL": "peripheral",
                "ISOLATED": "isolated",
            },
        ),
    },
    record_fields=[
        FieldDef("connection_count", int, 0),
        FieldDef("event_rate", float, 0.0),
        FieldDef("target_service", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="service_name",
)

# Backward-compatible re-exports
FlowPattern = EventDrivenTopologyMapper.FlowPattern
TopologyRole = EventDrivenTopologyMapper.TopologyRole
CentralityLevel = EventDrivenTopologyMapper.CentralityLevel
TopologyRecord = EventDrivenTopologyMapper.Record
TopologyAnalysis = EventDrivenTopologyMapper.Analysis
TopologyReport = EventDrivenTopologyMapper.Report
