"""Agent Specialization Scoring Engine — evaluate specialization depth, detect overfitting ris..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentSpecializationScoringEngine = engine(
    "AgentSpecializationScoringEngine",
    description="Score agent specialization effectiveness, detect overfitting risk, and rank...",
    enums={
        "specialization_type": EnumDef(
            "SpecializationType",
            {
                "DOMAIN": "domain",
                "TASK": "task",
                "SKILL": "skill",
                "ROLE": "role",
            },
        ),
        "depth": EnumDef(
            "SpecializationDepth",
            {
                "GENERALIST": "generalist",
                "MODERATE": "moderate",
                "SPECIALIST": "specialist",
                "EXPERT": "expert",
            },
        ),
        "effectiveness": EnumDef(
            "EffectivenessLevel",
            {
                "EXCEPTIONAL": "exceptional",
                "PROFICIENT": "proficient",
                "DEVELOPING": "developing",
                "INEFFECTIVE": "ineffective",
            },
        ),
    },
    record_fields=[
        FieldDef("generalization_score", float, 0.0),
        FieldDef("task_success_rate", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="specialization_score",
    key_field="agent_id",
)

# Backward-compatible re-exports
SpecializationType = AgentSpecializationScoringEngine.SpecializationType
SpecializationDepth = AgentSpecializationScoringEngine.SpecializationDepth
EffectivenessLevel = AgentSpecializationScoringEngine.EffectivenessLevel
SpecializationScoringRecord = AgentSpecializationScoringEngine.Record
SpecializationScoringAnalysis = AgentSpecializationScoringEngine.Analysis
SpecializationScoringReport = AgentSpecializationScoringEngine.Report
