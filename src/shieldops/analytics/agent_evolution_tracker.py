"""Agent Evolution Tracker Track generational progress of agent optimization with evolution ve..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentEvolutionTracker = engine(
    "AgentEvolutionTracker",
    description="Track generational progress with evolution velocity and dead-end detection.",
    enums={
        "stage": EnumDef(
            "EvolutionStage",
            {
                "INITIAL": "initial",
                "LEARNING": "learning",
                "OPTIMIZING": "optimizing",
                "MATURE": "mature",
            },
        ),
        "mutation": EnumDef(
            "MutationType",
            {
                "PARAMETER": "parameter",
                "ARCHITECTURE": "architecture",
                "STRATEGY": "strategy",
                "PROMPT": "prompt",
            },
        ),
        "pressure": EnumDef(
            "SelectionPressure",
            {
                "PERFORMANCE": "performance",
                "COST": "cost",
                "RELIABILITY": "reliability",
                "SPEED": "speed",
            },
        ),
    },
    record_fields=[
        FieldDef("generation", int, 0),
    ],
    score_field="fitness_score",
    key_field="agent_id",
)

# Backward-compatible re-exports
EvolutionStage = AgentEvolutionTracker.EvolutionStage
MutationType = AgentEvolutionTracker.MutationType
SelectionPressure = AgentEvolutionTracker.SelectionPressure
EvolutionRecord = AgentEvolutionTracker.Record
EvolutionAnalysis = AgentEvolutionTracker.Analysis
EvolutionReport = AgentEvolutionTracker.Report
