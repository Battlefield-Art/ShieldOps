"""Experiment Parameter Search Engine — select next parameters, compute sensitivity, and estim..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ExperimentParameterSearchEngine = engine(
    "ExperimentParameterSearchEngine",
    description="Select next parameters, compute sensitivity, and estimate remaining search...",
    enums={
        "strategy": EnumDef(
            "SearchStrategy",
            {
                "GRID_SEARCH": "grid_search",
                "RANDOM_SEARCH": "random_search",
                "BAYESIAN": "bayesian",
                "SUCCESSIVE_HALVING": "successive_halving",
            },
        ),
        "sensitivity": EnumDef(
            "ParameterSensitivity",
            {
                "HIGH_IMPACT": "high_impact",
                "MODERATE_IMPACT": "moderate_impact",
                "LOW_IMPACT": "low_impact",
                "NEGLIGIBLE": "negligible",
            },
        ),
        "phase": EnumDef(
            "SearchPhase",
            {
                "EXPLORATION": "exploration",
                "EXPLOITATION": "exploitation",
                "REFINEMENT": "refinement",
                "VERIFICATION": "verification",
            },
        ),
    },
    record_fields=[
        FieldDef("parameter_name", str, ""),
        FieldDef("parameter_value", float, 0.0),
        FieldDef("search_iteration", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="outcome_score",
    key_field="experiment_id",
)

# Backward-compatible re-exports
SearchStrategy = ExperimentParameterSearchEngine.SearchStrategy
ParameterSensitivity = ExperimentParameterSearchEngine.ParameterSensitivity
SearchPhase = ExperimentParameterSearchEngine.SearchPhase
ExperimentParameterRecord = ExperimentParameterSearchEngine.Record
ExperimentParameterAnalysis = ExperimentParameterSearchEngine.Analysis
ExperimentParameterReport = ExperimentParameterSearchEngine.Report
