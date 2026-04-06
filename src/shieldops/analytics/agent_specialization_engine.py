"""AgentSpecializationEngine — Track and optimize agent specialization."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentSpecializationEngine = engine(
    "AgentSpecializationEngine",
    description="Track and optimize agent specialization across task domains.",
    enums={
        "domain": EnumDef(
            "SpecializationDomain",
            {
                "INFRASTRUCTURE": "infrastructure",
                "SECURITY": "security",
                "COST": "cost",
                "COMPLIANCE": "compliance",
                "OBSERVABILITY": "observability",
            },
        ),
        "proficiency": EnumDef(
            "ProficiencyLevel",
            {
                "NOVICE": "novice",
                "COMPETENT": "competent",
                "PROFICIENT": "proficient",
                "EXPERT": "expert",
            },
        ),
        "adaptation": EnumDef(
            "AdaptationSpeed",
            {
                "FAST": "fast",
                "MODERATE": "moderate",
                "SLOW": "slow",
            },
        ),
    },
    record_fields=[
        FieldDef("task_count", int, 0),
        FieldDef("success_rate", float, 0.0),
    ],
)

# Backward-compatible re-exports
SpecializationDomain = AgentSpecializationEngine.SpecializationDomain
ProficiencyLevel = AgentSpecializationEngine.ProficiencyLevel
AdaptationSpeed = AgentSpecializationEngine.AdaptationSpeed
AgentSpecializationRecord = AgentSpecializationEngine.Record
AgentSpecializationAnalysis = AgentSpecializationEngine.Analysis
AgentSpecializationReport = AgentSpecializationEngine.Report
