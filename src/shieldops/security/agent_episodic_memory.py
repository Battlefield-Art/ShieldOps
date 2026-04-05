"""Agent Episodic Memory — store and recall agent experiences."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentEpisodicMemoryEngine = engine(
    "AgentEpisodicMemoryEngine",
    description="Store and recall agent episodic experiences.",
    enums={
        "scope": EnumDef(
            "MemoryScope",
            {
                "INVESTIGATION": "investigation",
                "INCIDENT": "incident",
                "REMEDIATION": "remediation",
                "DETECTION": "detection",
            },
        ),
        "retention": EnumDef(
            "RetentionPolicy",
            {
                "PERMANENT": "permanent",
                "YEARLY": "yearly",
                "QUARTERLY": "quarterly",
                "MONTHLY": "monthly",
            },
        ),
        "recall_accuracy": EnumDef(
            "RecallAccuracy",
            {
                "EXACT": "exact",
                "FUZZY": "fuzzy",
                "PARTIAL": "partial",
            },
        ),
    },
    record_fields=[
        FieldDef("summary", str, ""),
        FieldDef("context_keys", list, ""),
        FieldDef("outcome", str, ""),
        FieldDef("confidence", float, 0.0),
        FieldDef("decay_factor", float, 1.0),
    ],
    key_field="agent_id",
)

# Backward-compatible re-exports
MemoryScope = AgentEpisodicMemoryEngine.MemoryScope
RetentionPolicy = AgentEpisodicMemoryEngine.RetentionPolicy
RecallAccuracy = AgentEpisodicMemoryEngine.RecallAccuracy
EpisodeRecord = AgentEpisodicMemoryEngine.Record
EpisodeAnalysis = AgentEpisodicMemoryEngine.Analysis
EpisodeReport = AgentEpisodicMemoryEngine.Report
