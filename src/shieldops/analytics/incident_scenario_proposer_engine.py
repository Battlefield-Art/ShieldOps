"""Incident Scenario Proposer Engine — generates synthetic SRE incident scenarios of varying c..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IncidentScenarioProposerEngine = engine(
    "IncidentScenarioProposerEngine",
    description="Generates synthetic SRE incident scenarios of varying complexity.",
    enums={
        "complexity": EnumDef(
            "ScenarioComplexity",
            {
                "SINGLE_HOP": "single_hop",
                "TWO_HOP": "two_hop",
                "THREE_HOP": "three_hop",
                "FOUR_HOP": "four_hop",
            },
        ),
        "category": EnumDef(
            "ScenarioCategory",
            {
                "INFRASTRUCTURE": "infrastructure",
                "APPLICATION": "application",
                "SECURITY": "security",
                "CASCADING": "cascading",
            },
        ),
        "strategy": EnumDef(
            "ProposerStrategy",
            {
                "RANDOM": "random",
                "ADAPTIVE": "adaptive",
                "ADVERSARIAL": "adversarial",
                "CURRICULUM": "curriculum",
            },
        ),
    },
    record_fields=[
        FieldDef("difficulty_rating", float, 0.0),
        FieldDef("solver_success_rate", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="novelty_score",
    key_field="scenario_id",
)

# Backward-compatible re-exports
ScenarioComplexity = IncidentScenarioProposerEngine.ScenarioComplexity
ScenarioCategory = IncidentScenarioProposerEngine.ScenarioCategory
ProposerStrategy = IncidentScenarioProposerEngine.ProposerStrategy
IncidentScenarioRecord = IncidentScenarioProposerEngine.Record
IncidentScenarioAnalysis = IncidentScenarioProposerEngine.Analysis
IncidentScenarioReport = IncidentScenarioProposerEngine.Report
