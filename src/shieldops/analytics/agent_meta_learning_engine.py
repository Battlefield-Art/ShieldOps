"""AgentMetaLearningEngine — Meta-learning across agent fleet."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentMetaLearningEngine = engine(
    "AgentMetaLearningEngine",
    description="Meta-learning across agent fleet — learn what learning strategies work best.",
    enums={
        "meta_strategy": EnumDef(
            "MetaStrategy",
            {
                "TRANSFER": "transfer",
                "CURRICULUM": "curriculum",
                "ENSEMBLE": "ensemble",
                "DISTILLATION": "distillation",
            },
        ),
        "learning_outcome": EnumDef(
            "LearningOutcome",
            {
                "IMPROVED": "improved",
                "UNCHANGED": "unchanged",
                "DEGRADED": "degraded",
            },
        ),
        "agent_generation": EnumDef(
            "AgentGeneration",
            {
                "GEN1": "gen1",
                "GEN2": "gen2",
                "GEN3": "gen3",
                "EXPERIMENTAL": "experimental",
            },
        ),
    },
    record_fields=[
        FieldDef("improvement_pct", float, 0.0),
        FieldDef("training_cost", float, 0.0),
    ],
)

# Backward-compatible re-exports
MetaStrategy = AgentMetaLearningEngine.MetaStrategy
LearningOutcome = AgentMetaLearningEngine.LearningOutcome
AgentGeneration = AgentMetaLearningEngine.AgentGeneration
AgentMetaLearningRecord = AgentMetaLearningEngine.Record
AgentMetaLearningAnalysis = AgentMetaLearningEngine.Analysis
AgentMetaLearningReport = AgentMetaLearningEngine.Report
