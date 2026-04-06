"""Multi-Agent Coordination Engine — routing, load balancing, conflict resolution."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MultiAgentCoordinationEngine = engine(
    "MultiAgentCoordinationEngine",
    description="Optimize coordination between multiple agents — routing, conflicts.",
    enums={
        "coordination_mode": EnumDef(
            "CoordinationMode",
            {
                "SEQUENTIAL": "sequential",
                "PARALLEL": "parallel",
                "PIPELINE": "pipeline",
                "HIERARCHICAL": "hierarchical",
            },
        ),
        "conflict_type": EnumDef(
            "ConflictType",
            {
                "RESOURCE_CONTENTION": "resource_contention",
                "ACTION_CONFLICT": "action_conflict",
                "STATE_INCONSISTENCY": "state_inconsistency",
                "PRIORITY_CLASH": "priority_clash",
            },
        ),
        "resolution_strategy": EnumDef(
            "ResolutionStrategy",
            {
                "PRIORITY_BASED": "priority_based",
                "CONSENSUS": "consensus",
                "TIMEOUT": "timeout",
                "ESCALATION": "escalation",
            },
        ),
    },
    record_fields=[
        FieldDef("overhead_ms", float, 0.0),
    ],
    key_field="task_id",
)

# Backward-compatible re-exports
CoordinationMode = MultiAgentCoordinationEngine.CoordinationMode
ConflictType = MultiAgentCoordinationEngine.ConflictType
ResolutionStrategy = MultiAgentCoordinationEngine.ResolutionStrategy
CoordinationRecord = MultiAgentCoordinationEngine.Record
CoordinationAnalysis = MultiAgentCoordinationEngine.Analysis
CoordinationReport = MultiAgentCoordinationEngine.Report
