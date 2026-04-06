"""AgentEvolutionTrackerEngine — Track agent capability evolution over time."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentEvolutionTrackerEngine = engine(
    "AgentEvolutionTrackerEngine",
    description="Track agent capability evolution over time.",
    enums={
        "evolution_phase": EnumDef(
            "EvolutionPhase",
            {
                "BOOTSTRAP": "bootstrap",
                "LEARNING": "learning",
                "PROFICIENT": "proficient",
                "EXPERT": "expert",
                "PLATEAU": "plateau",
            },
        ),
        "capability_domain": EnumDef(
            "CapabilityDomain",
            {
                "INVESTIGATION": "investigation",
                "REMEDIATION": "remediation",
                "SECURITY": "security",
                "OPTIMIZATION": "optimization",
            },
        ),
        "evolution_trend": EnumDef(
            "EvolutionTrend",
            {
                "ACCELERATING": "accelerating",
                "STEADY": "steady",
                "DECELERATING": "decelerating",
                "REGRESSING": "regressing",
            },
        ),
    },
    record_fields=[
        FieldDef("version", str, ""),
        FieldDef("skill_count", int, 0),
    ],
)

# Backward-compatible re-exports
EvolutionPhase = AgentEvolutionTrackerEngine.EvolutionPhase
CapabilityDomain = AgentEvolutionTrackerEngine.CapabilityDomain
EvolutionTrend = AgentEvolutionTrackerEngine.EvolutionTrend
AgentEvolutionTrackerRecord = AgentEvolutionTrackerEngine.Record
AgentEvolutionTrackerAnalysis = AgentEvolutionTrackerEngine.Analysis
AgentEvolutionTrackerReport = AgentEvolutionTrackerEngine.Report
