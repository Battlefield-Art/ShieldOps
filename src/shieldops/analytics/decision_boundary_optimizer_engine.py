"""Decision Boundary Optimizer Engine — evaluate boundary quality, detect boundary drift, and..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DecisionBoundaryOptimizerEngine = engine(
    "DecisionBoundaryOptimizerEngine",
    description="Optimize agent decision boundaries, detect boundary drift, and tune decisio...",
    enums={
        "boundary_type": EnumDef(
            "BoundaryType",
            {
                "LINEAR": "linear",
                "NONLINEAR": "nonlinear",
                "ENSEMBLE": "ensemble",
                "ADAPTIVE": "adaptive",
            },
        ),
        "optimization_method": EnumDef(
            "OptimizationMethod",
            {
                "GRADIENT": "gradient",
                "EVOLUTIONARY": "evolutionary",
                "BAYESIAN": "bayesian",
                "REINFORCEMENT": "reinforcement",
            },
        ),
        "boundary_quality": EnumDef(
            "BoundaryQuality",
            {
                "SHARP": "sharp",
                "FUZZY": "fuzzy",
                "NOISY": "noisy",
                "OPTIMAL": "optimal",
            },
        ),
    },
    record_fields=[
        FieldDef("false_positive_rate", float, 0.0),
        FieldDef("false_negative_rate", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="accuracy_score",
    key_field="agent_id",
)

# Backward-compatible re-exports
BoundaryType = DecisionBoundaryOptimizerEngine.BoundaryType
OptimizationMethod = DecisionBoundaryOptimizerEngine.OptimizationMethod
BoundaryQuality = DecisionBoundaryOptimizerEngine.BoundaryQuality
DecisionBoundaryRecord = DecisionBoundaryOptimizerEngine.Record
DecisionBoundaryAnalysis = DecisionBoundaryOptimizerEngine.Analysis
DecisionBoundaryReport = DecisionBoundaryOptimizerEngine.Report
