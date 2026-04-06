"""AgentCollaborationOptimizerEngine — Optimize how agents collaborate on complex tasks."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentCollaborationOptimizerEngine = engine(
    "AgentCollaborationOptimizerEngine",
    description="Optimize how agents collaborate on complex tasks.",
    enums={
        "collaboration_mode": EnumDef(
            "CollaborationMode",
            {
                "SEQUENTIAL": "sequential",
                "PARALLEL": "parallel",
                "CONSENSUS": "consensus",
                "HIERARCHICAL": "hierarchical",
            },
        ),
        "handoff_quality": EnumDef(
            "HandoffQuality",
            {
                "CLEAN": "clean",
                "PARTIAL": "partial",
                "FAILED": "failed",
                "REDUNDANT": "redundant",
            },
        ),
        "conflict_type": EnumDef(
            "ConflictType",
            {
                "RESOURCE": "resource",
                "PRIORITY": "priority",
                "DATA": "data",
                "DECISION": "decision",
            },
        ),
    },
    record_fields=[
        FieldDef("agent_count", int, 0),
        FieldDef("latency_ms", float, 0.0),
    ],
)

# Backward-compatible re-exports
CollaborationMode = AgentCollaborationOptimizerEngine.CollaborationMode
HandoffQuality = AgentCollaborationOptimizerEngine.HandoffQuality
ConflictType = AgentCollaborationOptimizerEngine.ConflictType
AgentCollaborationOptimizerRecord = AgentCollaborationOptimizerEngine.Record
AgentCollaborationOptimizerAnalysis = AgentCollaborationOptimizerEngine.Analysis
AgentCollaborationOptimizerReport = AgentCollaborationOptimizerEngine.Report
