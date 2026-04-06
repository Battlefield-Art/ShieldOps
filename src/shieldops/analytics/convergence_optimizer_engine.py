"""Convergence Optimizer Engine — optimize self-learning loop convergence, detect plateau, adj..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ConvergenceOptimizerEngine = engine(
    "ConvergenceOptimizerEngine",
    description="Optimize self-learning loop convergence — detect plateau, adjust learning r...",
    enums={
        "convergence_phase": EnumDef(
            "ConvergencePhase",
            {
                "WARMING_UP": "warming_up",
                "IMPROVING": "improving",
                "PLATEAU": "plateau",
                "DIVERGING": "diverging",
            },
        ),
        "optimization_action": EnumDef(
            "OptimizationAction",
            {
                "CONTINUE": "continue",
                "ADJUST_RATE": "adjust_rate",
                "EARLY_STOP": "early_stop",
                "RESTART": "restart",
            },
        ),
        "learning_rate_strategy": EnumDef(
            "LearningRateStrategy",
            {
                "CONSTANT": "constant",
                "DECAY": "decay",
                "ADAPTIVE": "adaptive",
                "COSINE": "cosine",
            },
        ),
    },
    record_fields=[
        FieldDef("metric_value", float, 0.0),
        FieldDef("metric_delta", float, 0.0),
        FieldDef("iteration", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="loop_id",
)

# Backward-compatible re-exports
ConvergencePhase = ConvergenceOptimizerEngine.ConvergencePhase
OptimizationAction = ConvergenceOptimizerEngine.OptimizationAction
LearningRateStrategy = ConvergenceOptimizerEngine.LearningRateStrategy
ConvergenceOptimizerRecord = ConvergenceOptimizerEngine.Record
ConvergenceOptimizerAnalysis = ConvergenceOptimizerEngine.Analysis
ConvergenceOptimizerReport = ConvergenceOptimizerEngine.Report
