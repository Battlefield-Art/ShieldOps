"""Synthetic Scenario Quality Engine — evaluates quality of generated incident scenarios."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SyntheticScenarioQualityEngine = engine(
    "SyntheticScenarioQualityEngine",
    description="Evaluates quality of generated incident scenarios.",
    enums={
        "realism": EnumDef(
            "ScenarioRealism",
            {
                "REALISTIC": "realistic",
                "PLAUSIBLE": "plausible",
                "UNLIKELY": "unlikely",
                "DEGENERATE": "degenerate",
            },
        ),
        "dimension": EnumDef(
            "QualityDimension",
            {
                "SOLVABILITY": "solvability",
                "DIVERSITY": "diversity",
                "RELEVANCE": "relevance",
                "COMPLEXITY": "complexity",
            },
        ),
        "verdict": EnumDef(
            "QualityVerdict",
            {
                "ACCEPTED": "accepted",
                "MARGINAL": "marginal",
                "REJECTED": "rejected",
                "NEEDS_REVISION": "needs_revision",
            },
        ),
    },
    record_fields=[
        FieldDef("diversity_score", float, 0.0),
        FieldDef("complexity_score", float, 0.0),
        FieldDef("overall_quality", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="realism_score",
    key_field="scenario_id",
)

# Backward-compatible re-exports
ScenarioRealism = SyntheticScenarioQualityEngine.ScenarioRealism
QualityDimension = SyntheticScenarioQualityEngine.QualityDimension
QualityVerdict = SyntheticScenarioQualityEngine.QualityVerdict
ScenarioQualityRecord = SyntheticScenarioQualityEngine.Record
ScenarioQualityAnalysis = SyntheticScenarioQualityEngine.Analysis
ScenarioQualityReport = SyntheticScenarioQualityEngine.Report
