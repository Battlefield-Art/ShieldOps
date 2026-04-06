"""Swarm Intelligence Engine — analyze multi-agent swarm coordination, identify bottleneck age..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SwarmIntelligenceEngine = engine(
    "SwarmIntelligenceEngine",
    description="Analyze multi-agent swarm coordination, identify bottleneck agents, and opt...",
    enums={
        "swarm_role": EnumDef(
            "SwarmRole",
            {
                "LEADER": "leader",
                "WORKER": "worker",
                "OBSERVER": "observer",
                "COORDINATOR": "coordinator",
            },
        ),
        "coordination_pattern": EnumDef(
            "CoordinationPattern",
            {
                "CONSENSUS": "consensus",
                "AUCTION": "auction",
                "VOTING": "voting",
                "DELEGATION": "delegation",
            },
        ),
        "swarm_health": EnumDef(
            "SwarmHealth",
            {
                "OPTIMAL": "optimal",
                "DEGRADED": "degraded",
                "FRAGMENTED": "fragmented",
                "FAILED": "failed",
            },
        ),
    },
    record_fields=[
        FieldDef("swarm_id", str, ""),
        FieldDef("task_completion_rate", float, 0.0),
        FieldDef("response_time_seconds", float, 0.0),
        FieldDef("messages_sent", int, 0),
        FieldDef("tasks_assigned", int, 0),
        FieldDef("tasks_completed", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="agent_id",
)

# Backward-compatible re-exports
SwarmRole = SwarmIntelligenceEngine.SwarmRole
CoordinationPattern = SwarmIntelligenceEngine.CoordinationPattern
SwarmHealth = SwarmIntelligenceEngine.SwarmHealth
SwarmIntelligenceRecord = SwarmIntelligenceEngine.Record
SwarmIntelligenceAnalysis = SwarmIntelligenceEngine.Analysis
SwarmIntelligenceReport = SwarmIntelligenceEngine.Report
