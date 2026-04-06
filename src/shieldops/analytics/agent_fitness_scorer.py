"""Agent Fitness Scorer Compute composite fitness scores for agents across multiple dimensions..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentFitnessScorer = engine(
    "AgentFitnessScorer",
    description="Compute composite fitness scores for agents with plateau detection and impr...",
    enums={
        "dimension": EnumDef(
            "FitnessDimension",
            {
                "ACCURACY": "accuracy",
                "SPEED": "speed",
                "COST": "cost",
                "RELIABILITY": "reliability",
            },
        ),
        "method": EnumDef(
            "ScoringMethod",
            {
                "WEIGHTED_SUM": "weighted_sum",
                "PARETO": "pareto",
                "TOURNAMENT": "tournament",
                "ELO": "elo",
            },
        ),
        "trend": EnumDef(
            "FitnessTrend",
            {
                "IMPROVING": "improving",
                "PLATEAUED": "plateaued",
                "DECLINING": "declining",
                "VOLATILE": "volatile",
            },
        ),
    },
    record_fields=[
        FieldDef("generation", int, 0),
    ],
    key_field="agent_id",
)

# Backward-compatible re-exports
FitnessDimension = AgentFitnessScorer.FitnessDimension
ScoringMethod = AgentFitnessScorer.ScoringMethod
FitnessTrend = AgentFitnessScorer.FitnessTrend
FitnessRecord = AgentFitnessScorer.Record
FitnessAnalysis = AgentFitnessScorer.Analysis
FitnessReport = AgentFitnessScorer.Report
