"""Triage Routing Optimizer Engine — optimize incident routing to teams."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TriageRoutingOptimizerEngine = engine(
    "TriageRoutingOptimizerEngine",
    description="Triage Routing Optimizer Engine — optimize incident routing to teams.",
    enums={
        "routing_strategy": EnumDef(
            "RoutingStrategy",
            {
                "SKILL_BASED": "skill_based",
                "LOAD_BALANCED": "load_balanced",
                "ROUND_ROBIN": "round_robin",
                "ESCALATION": "escalation",
                "AI_RECOMMENDED": "ai_recommended",
            },
        ),
        "routing_outcome": EnumDef(
            "RoutingOutcome",
            {
                "CORRECT_FIRST_TIME": "correct_first_time",
                "REROUTED": "rerouted",
                "ESCALATED": "escalated",
                "BOUNCED": "bounced",
                "TIMEOUT": "timeout",
            },
        ),
        "team_load": EnumDef(
            "TeamLoad",
            {
                "UNDER": "under",
                "OPTIMAL": "optimal",
                "HEAVY": "heavy",
                "OVERLOADED": "overloaded",
                "UNAVAILABLE": "unavailable",
            },
        ),
    },
    record_fields=[
        FieldDef("assigned_team", str, ""),
        FieldDef("reroute_count", int, 0),
        FieldDef("time_to_assign_ms", float, 0.0),
    ],
    key_field="incident_id",
)

# Backward-compatible re-exports
RoutingStrategy = TriageRoutingOptimizerEngine.RoutingStrategy
RoutingOutcome = TriageRoutingOptimizerEngine.RoutingOutcome
TeamLoad = TriageRoutingOptimizerEngine.TeamLoad
TriageRoutingRecord = TriageRoutingOptimizerEngine.Record
TriageRoutingAnalysis = TriageRoutingOptimizerEngine.Analysis
TriageRoutingReport = TriageRoutingOptimizerEngine.Report
