"""PlatformEvolutionPlanner — platform evolution planner."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PlatformEvolutionPlanner = engine(
    "PlatformEvolutionPlanner",
    module="operations",  # uses record_item
    description="Platform Evolution Planner.",
    enums={
        "evolution_phase": EnumDef(
            "EvolutionPhase",
            {
                "FOUNDATION": "foundation",
                "GROWTH": "growth",
                "OPTIMIZATION": "optimization",
                "TRANSFORMATION": "transformation",
                "INNOVATION": "innovation",
            },
        ),
        "evolution_priority": EnumDef(
            "EvolutionPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "ASPIRATIONAL": "aspirational",
            },
        ),
        "evolution_risk": EnumDef(
            "EvolutionRisk",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "MINIMAL": "minimal",
                "NONE": "none",
            },
        ),
    },
)

# Backward-compatible re-exports
EvolutionPhase = PlatformEvolutionPlanner.EvolutionPhase
EvolutionPriority = PlatformEvolutionPlanner.EvolutionPriority
EvolutionRisk = PlatformEvolutionPlanner.EvolutionRisk
PlatformEvolutionPlannerRecord = PlatformEvolutionPlanner.Record
PlatformEvolutionPlannerAnalysis = PlatformEvolutionPlanner.Analysis
PlatformEvolutionPlannerReport = PlatformEvolutionPlanner.Report
