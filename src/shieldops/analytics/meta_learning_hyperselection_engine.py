"""Meta-Learning Hyperselection Engine — meta-learn optimal hyperparameters, evaluate search s..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MetaLearningHyperselectionEngine = engine(
    "MetaLearningHyperselectionEngine",
    description="Meta-learn optimal hyperparameters, evaluate search strategies, and rank co...",
    enums={
        "search_strategy": EnumDef(
            "SearchStrategy",
            {
                "GRID": "grid",
                "RANDOM": "random",
                "BAYESIAN": "bayesian",
                "EVOLUTIONARY": "evolutionary",
            },
        ),
        "hyperparam_type": EnumDef(
            "HyperparamType",
            {
                "LEARNING_RATE": "learning_rate",
                "BATCH_SIZE": "batch_size",
                "ARCHITECTURE": "architecture",
                "REGULARIZATION": "regularization",
            },
        ),
        "outcome": EnumDef(
            "SelectionOutcome",
            {
                "IMPROVED": "improved",
                "UNCHANGED": "unchanged",
                "DEGRADED": "degraded",
                "FAILED": "failed",
            },
        ),
    },
    record_fields=[
        FieldDef("iterations_used", int, 0),
        FieldDef("search_budget", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="performance_score",
    key_field="agent_id",
)

# Backward-compatible re-exports
SearchStrategy = MetaLearningHyperselectionEngine.SearchStrategy
HyperparamType = MetaLearningHyperselectionEngine.HyperparamType
SelectionOutcome = MetaLearningHyperselectionEngine.SelectionOutcome
HyperselectionRecord = MetaLearningHyperselectionEngine.Record
HyperselectionAnalysis = MetaLearningHyperselectionEngine.Analysis
HyperselectionReport = MetaLearningHyperselectionEngine.Report
