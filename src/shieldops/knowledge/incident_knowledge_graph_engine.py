"""Incident Knowledge Graph Engine — compute knowledge connections, detect knowledge gaps, ran..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IncidentKnowledgeGraphEngine = engine(
    "IncidentKnowledgeGraphEngine",
    description="Compute knowledge connections, detect knowledge gaps, rank nodes by inciden...",
    enums={
        "node_type": EnumDef(
            "NodeType",
            {
                "INCIDENT": "incident",
                "ROOT_CAUSE": "root_cause",
                "SERVICE": "service",
                "TEAM": "team",
            },
        ),
        "edge_type": EnumDef(
            "EdgeType",
            {
                "CAUSED_BY": "caused_by",
                "AFFECTED": "affected",
                "RESOLVED_BY": "resolved_by",
                "PREVENTED": "prevented",
            },
        ),
        "graph_scope": EnumDef(
            "GraphScope",
            {
                "SERVICE": "service",
                "TEAM": "team",
                "ORGANIZATION": "organization",
                "CROSS_ORG": "cross_org",
            },
        ),
    },
    record_fields=[
        FieldDef("target_node", str, ""),
        FieldDef("weight", float, 1.0),
        FieldDef("description", str, ""),
    ],
    key_field="source_node",
)

# Backward-compatible re-exports
NodeType = IncidentKnowledgeGraphEngine.NodeType
EdgeType = IncidentKnowledgeGraphEngine.EdgeType
GraphScope = IncidentKnowledgeGraphEngine.GraphScope
KnowledgeGraphRecord = IncidentKnowledgeGraphEngine.Record
KnowledgeGraphAnalysis = IncidentKnowledgeGraphEngine.Analysis
KnowledgeGraphReport = IncidentKnowledgeGraphEngine.Report
