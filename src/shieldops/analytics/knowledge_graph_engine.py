"""KnowledgeGraphEngine — Build and query an agent knowledge graph."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

KnowledgeGraphEngine = engine(
    "KnowledgeGraphEngine",
    description="Build and query an agent knowledge graph.",
    enums={
        "entity_type": EnumDef(
            "EntityType",
            {
                "SERVICE": "service",
                "INFRASTRUCTURE": "infrastructure",
                "INCIDENT": "incident",
                "RUNBOOK": "runbook",
                "PERSON": "person",
            },
        ),
        "relationship": EnumDef(
            "RelationshipType",
            {
                "DEPENDS_ON": "depends_on",
                "CAUSES": "causes",
                "RESOLVES": "resolves",
                "OWNS": "owns",
                "MONITORS": "monitors",
            },
        ),
        "health": EnumDef(
            "GraphHealth",
            {
                "CONNECTED": "connected",
                "FRAGMENTED": "fragmented",
                "STALE": "stale",
            },
        ),
    },
    record_fields=[
        FieldDef("edge_count", int, 0),
        FieldDef("staleness_days", int, 0),
    ],
)

# Backward-compatible re-exports
EntityType = KnowledgeGraphEngine.EntityType
RelationshipType = KnowledgeGraphEngine.RelationshipType
GraphHealth = KnowledgeGraphEngine.GraphHealth
KnowledgeGraphRecord = KnowledgeGraphEngine.Record
KnowledgeGraphAnalysis = KnowledgeGraphEngine.Analysis
KnowledgeGraphReport = KnowledgeGraphEngine.Report
