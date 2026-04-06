"""Solver Performance Evolution Engine — tracks SRE agent performance across co-evolution iter..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SolverPerformanceEvolutionEngine = engine(
    "SolverPerformanceEvolutionEngine",
    description="Tracks SRE agent (solver) performance across co-evolution iterations.",
    enums={
        "phase": EnumDef(
            "EvolutionPhase",
            {
                "WARMUP": "warmup",
                "RAPID_GAIN": "rapid_gain",
                "PLATEAU": "plateau",
                "CONVERGENCE": "convergence",
            },
        ),
        "skill_level": EnumDef(
            "SolverSkillLevel",
            {
                "NOVICE": "novice",
                "COMPETENT": "competent",
                "PROFICIENT": "proficient",
                "EXPERT": "expert",
            },
        ),
        "trend": EnumDef(
            "PerformanceTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DECLINING": "declining",
                "OSCILLATING": "oscillating",
            },
        ),
    },
    record_fields=[
        FieldDef("iteration", int, 0),
        FieldDef("success_rate", float, 0.0),
        FieldDef("scenario_difficulty", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="reward_score",
    key_field="solver_id",
)

# Backward-compatible re-exports
EvolutionPhase = SolverPerformanceEvolutionEngine.EvolutionPhase
SolverSkillLevel = SolverPerformanceEvolutionEngine.SolverSkillLevel
PerformanceTrend = SolverPerformanceEvolutionEngine.PerformanceTrend
SolverPerformanceRecord = SolverPerformanceEvolutionEngine.Record
SolverPerformanceAnalysis = SolverPerformanceEvolutionEngine.Analysis
SolverPerformanceReport = SolverPerformanceEvolutionEngine.Report
