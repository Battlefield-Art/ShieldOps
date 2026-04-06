"""Model Self-Tuning Engine Automated model hyperparameter optimization with convergence detec..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ModelSelfTuningEngine = engine(
    "ModelSelfTuningEngine",
    description="Automated model hyperparameter optimization with convergence detection.",
    enums={
        "dimension": EnumDef(
            "TuningDimension",
            {
                "LEARNING_RATE": "learning_rate",
                "BATCH_SIZE": "batch_size",
                "TEMPERATURE": "temperature",
                "TOP_P": "top_p",
            },
        ),
        "strategy": EnumDef(
            "TuningStrategy",
            {
                "GRID_SEARCH": "grid_search",
                "BAYESIAN": "bayesian",
                "RANDOM": "random",
                "ADAPTIVE": "adaptive",
            },
        ),
        "convergence": EnumDef(
            "ConvergenceStatus",
            {
                "CONVERGING": "converging",
                "OSCILLATING": "oscillating",
                "DIVERGING": "diverging",
                "CONVERGED": "converged",
            },
        ),
    },
    record_fields=[
        FieldDef("metric_value", float, 0.0),
        FieldDef("param_value", float, 0.0),
        FieldDef("iteration", int, 0),
    ],
    key_field="model_id",
)

# Backward-compatible re-exports
TuningDimension = ModelSelfTuningEngine.TuningDimension
TuningStrategy = ModelSelfTuningEngine.TuningStrategy
ConvergenceStatus = ModelSelfTuningEngine.ConvergenceStatus
TuningRecord = ModelSelfTuningEngine.Record
TuningAnalysis = ModelSelfTuningEngine.Analysis
TuningReport = ModelSelfTuningEngine.Report
