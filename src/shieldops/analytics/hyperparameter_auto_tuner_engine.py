"""Hyperparameter Auto-Tuner Engine — autoresearch-style agent parameter tuning."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

HyperparameterAutoTunerEngine = engine(
    "HyperparameterAutoTunerEngine",
    description="Automatically tune agent hyperparameters using propose-evaluate-accept/reject.",
    enums={
        "strategy": EnumDef(
            "TuningStrategy",
            {
                "GRID_SEARCH": "grid_search",
                "RANDOM_SEARCH": "random_search",
                "BAYESIAN": "bayesian",
                "EVOLUTIONARY": "evolutionary",
            },
        ),
        "parameter_type": EnumDef(
            "ParameterType",
            {
                "THRESHOLD": "threshold",
                "TIMEOUT": "timeout",
                "BATCH_SIZE": "batch_size",
                "LEARNING_RATE": "learning_rate",
            },
        ),
        "outcome": EnumDef(
            "TuningOutcome",
            {
                "IMPROVED": "improved",
                "NO_CHANGE": "no_change",
                "DEGRADED": "degraded",
                "INVALID": "invalid",
            },
        ),
    },
    key_field="agent_id",
)

# Backward-compatible re-exports
TuningStrategy = HyperparameterAutoTunerEngine.TuningStrategy
ParameterType = HyperparameterAutoTunerEngine.ParameterType
TuningOutcome = HyperparameterAutoTunerEngine.TuningOutcome
TuningRecord = HyperparameterAutoTunerEngine.Record
TuningAnalysis = HyperparameterAutoTunerEngine.Analysis
TuningReport = HyperparameterAutoTunerEngine.Report
