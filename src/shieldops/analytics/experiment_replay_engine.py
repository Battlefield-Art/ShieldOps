"""ExperimentReplayEngine — replay and analyze past experiments for meta-learning."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ExperimentReplayEngine = engine(
    "ExperimentReplayEngine",
    description="Replay and analyze past experiments for meta-learning.",
    enums={
        "replay_outcome": EnumDef(
            "ReplayOutcome",
            {
                "CONFIRMED": "confirmed",
                "CONTRADICTED": "contradicted",
                "INCONCLUSIVE": "inconclusive",
            },
        ),
        "insight_type": EnumDef(
            "InsightType",
            {
                "CAUSAL": "causal",
                "CORRELATIONAL": "correlational",
                "SPURIOUS": "spurious",
            },
        ),
        "replay_strategy": EnumDef(
            "ReplayStrategy",
            {
                "EXACT": "exact",
                "PERTURBED": "perturbed",
                "COUNTERFACTUAL": "counterfactual",
            },
        ),
    },
    record_fields=[
        FieldDef("original_score", float, 0.0),
        FieldDef("replay_score", float, 0.0),
        FieldDef("experiment_id", str, ""),
    ],
)

# Backward-compatible re-exports
ReplayOutcome = ExperimentReplayEngine.ReplayOutcome
InsightType = ExperimentReplayEngine.InsightType
ReplayStrategy = ExperimentReplayEngine.ReplayStrategy
ExperimentReplayRecord = ExperimentReplayEngine.Record
ExperimentReplayAnalysis = ExperimentReplayEngine.Analysis
ExperimentReplayReport = ExperimentReplayEngine.Report
