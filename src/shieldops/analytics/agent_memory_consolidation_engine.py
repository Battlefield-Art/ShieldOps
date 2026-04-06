"""Agent Memory Consolidation Engine — evaluate memory retention, detect knowledge decay, and..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentMemoryConsolidationEngine = engine(
    "AgentMemoryConsolidationEngine",
    description="Consolidate agent learning into long-term memory, detect knowledge decay, a...",
    enums={
        "memory_type": EnumDef(
            "MemoryType",
            {
                "EPISODIC": "episodic",
                "SEMANTIC": "semantic",
                "PROCEDURAL": "procedural",
                "WORKING": "working",
            },
        ),
        "phase": EnumDef(
            "ConsolidationPhase",
            {
                "ENCODING": "encoding",
                "STORAGE": "storage",
                "RETRIEVAL": "retrieval",
                "PRUNING": "pruning",
            },
        ),
        "retention_quality": EnumDef(
            "RetentionQuality",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "DEGRADED": "degraded",
                "LOST": "lost",
            },
        ),
    },
    record_fields=[
        FieldDef("decay_rate", float, 0.0),
        FieldDef("memory_size_mb", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="retention_score",
    key_field="agent_id",
)

# Backward-compatible re-exports
MemoryType = AgentMemoryConsolidationEngine.MemoryType
ConsolidationPhase = AgentMemoryConsolidationEngine.ConsolidationPhase
RetentionQuality = AgentMemoryConsolidationEngine.RetentionQuality
MemoryConsolidationRecord = AgentMemoryConsolidationEngine.Record
MemoryConsolidationAnalysis = AgentMemoryConsolidationEngine.Analysis
MemoryConsolidationReport = AgentMemoryConsolidationEngine.Report
