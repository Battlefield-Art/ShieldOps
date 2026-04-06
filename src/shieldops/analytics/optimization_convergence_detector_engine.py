"""Optimization Convergence Detector Engine — test convergence, distinguish local from global..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OptimizationConvergenceDetectorEngine = engine(
    "OptimizationConvergenceDetectorEngine",
    description="Test convergence, distinguish local from global optima, and recommend escap...",
    enums={
        "convergence_type": EnumDef(
            "ConvergenceType",
            {
                "GLOBAL_OPTIMUM": "global_optimum",
                "LOCAL_OPTIMUM": "local_optimum",
                "SADDLE_POINT": "saddle_point",
                "NOT_CONVERGED": "not_converged",
            },
        ),
        "convergence_test": EnumDef(
            "ConvergenceTest",
            {
                "GRADIENT_NORM": "gradient_norm",
                "IMPROVEMENT_RATE": "improvement_rate",
                "PARAMETER_STABILITY": "parameter_stability",
                "ENSEMBLE_AGREEMENT": "ensemble_agreement",
            },
        ),
        "escape_strategy": EnumDef(
            "EscapeStrategy",
            {
                "PERTURBATION": "perturbation",
                "RESTART": "restart",
                "WIDER_SEARCH": "wider_search",
                "ACCEPT_CONVERGENCE": "accept_convergence",
            },
        ),
    },
    record_fields=[
        FieldDef("metric_value", float, 0.0),
        FieldDef("gradient_norm", float, 0.0),
        FieldDef("improvement_rate", float, 0.0),
        FieldDef("iteration", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="experiment_id",
)

# Backward-compatible re-exports
ConvergenceType = OptimizationConvergenceDetectorEngine.ConvergenceType
ConvergenceTest = OptimizationConvergenceDetectorEngine.ConvergenceTest
EscapeStrategy = OptimizationConvergenceDetectorEngine.EscapeStrategy
OptimizationConvergenceRecord = OptimizationConvergenceDetectorEngine.Record
OptimizationConvergenceAnalysis = OptimizationConvergenceDetectorEngine.Analysis
OptimizationConvergenceReport = OptimizationConvergenceDetectorEngine.Report
