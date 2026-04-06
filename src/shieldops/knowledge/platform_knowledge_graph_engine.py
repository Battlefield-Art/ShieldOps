"""PlatformKnowledgeGraphEngine — platform knowledge graph engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PlatformKnowledgeGraphEngine = engine(
    "PlatformKnowledgeGraphEngine",
    module="operations",  # uses record_item
    description="Platform Knowledge Graph Engine.",
    enums={
        "node_type": EnumDef(
            "NodeType",
            {
                "SERVICE": "service",
                "TEAM": "team",
                "INCIDENT": "incident",
                "RUNBOOK": "runbook",
                "CONFIGURATION": "configuration",
            },
        ),
        "relation_type": EnumDef(
            "RelationType",
            {
                "DEPENDS_ON": "depends_on",
                "OWNS": "owns",
                "RESOLVES": "resolves",
                "TRIGGERS": "triggers",
                "DOCUMENTS": "documents",
            },
        ),
        "graph_insight": EnumDef(
            "GraphInsight",
            {
                "CRITICAL_PATH": "critical_path",
                "BOTTLENECK": "bottleneck",
                "ORPHAN": "orphan",
                "CYCLE": "cycle",
                "CLUSTER": "cluster",
            },
        ),
    },
)

# Backward-compatible re-exports
NodeType = PlatformKnowledgeGraphEngine.NodeType
RelationType = PlatformKnowledgeGraphEngine.RelationType
GraphInsight = PlatformKnowledgeGraphEngine.GraphInsight
PlatformKnowledgeGraphEngineRecord = PlatformKnowledgeGraphEngine.Record
PlatformKnowledgeGraphEngineAnalysis = PlatformKnowledgeGraphEngine.Analysis
PlatformKnowledgeGraphEngineReport = PlatformKnowledgeGraphEngine.Report
