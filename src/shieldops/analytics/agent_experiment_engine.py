"""Agent Experiment Engine Hypothesis-driven experiment loops for agent optimization with sing..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentExperimentEngine = engine(
    "AgentExperimentEngine",
    description="Hypothesis-driven experiment loops for agent optimization with single-metri...",
    enums={
        "experiment_type": EnumDef(
            "ExperimentType",
            {
                "HYPERPARAMETER": "hyperparameter",
                "ARCHITECTURE": "architecture",
                "PROMPT": "prompt",
                "STRATEGY": "strategy",
            },
        ),
        "outcome": EnumDef(
            "ExperimentOutcome",
            {
                "IMPROVED": "improved",
                "DEGRADED": "degraded",
                "NEUTRAL": "neutral",
                "INCONCLUSIVE": "inconclusive",
            },
        ),
        "resource_budget": EnumDef(
            "ResourceBudget",
            {
                "MINIMAL": "minimal",
                "STANDARD": "standard",
                "EXTENDED": "extended",
                "UNLIMITED": "unlimited",
            },
        ),
    },
    record_fields=[
        FieldDef("experiment_name", str, ""),
        FieldDef("metric_value", float, 0.0),
        FieldDef("baseline_value", float, 0.0),
    ],
    key_field="agent_id",
)

# Backward-compatible re-exports
ExperimentType = AgentExperimentEngine.ExperimentType
ExperimentOutcome = AgentExperimentEngine.ExperimentOutcome
ResourceBudget = AgentExperimentEngine.ResourceBudget
ExperimentRecord = AgentExperimentEngine.Record
ExperimentAnalysis = AgentExperimentEngine.Analysis
ExperimentReport = AgentExperimentEngine.Report
