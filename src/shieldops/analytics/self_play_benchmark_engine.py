"""Self Play Benchmark Engine — benchmarks self-play vs supervised performance."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SelfPlayBenchmarkEngine = engine(
    "SelfPlayBenchmarkEngine",
    description="Benchmarks self-play vs supervised performance.",
    enums={
        "paradigm": EnumDef(
            "TrainingParadigm",
            {
                "SELF_PLAY": "self_play",
                "SUPERVISED": "supervised",
                "SEMI_SUPERVISED": "semi_supervised",
                "HYBRID": "hybrid",
            },
        ),
        "metric": EnumDef(
            "BenchmarkMetric",
            {
                "ACCURACY": "accuracy",
                "EFFICIENCY": "efficiency",
                "GENERALIZATION": "generalization",
                "ROBUSTNESS": "robustness",
            },
        ),
        "outcome": EnumDef(
            "ComparisonOutcome",
            {
                "SELF_PLAY_WINS": "self_play_wins",
                "SUPERVISED_WINS": "supervised_wins",
                "TIE": "tie",
                "INCONCLUSIVE": "inconclusive",
            },
        ),
    },
    record_fields=[
        FieldDef("baseline_score", float, 0.0),
        FieldDef("data_efficiency", float, 0.0),
        FieldDef("generalization_gap", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="benchmark_id",
)

# Backward-compatible re-exports
TrainingParadigm = SelfPlayBenchmarkEngine.TrainingParadigm
BenchmarkMetric = SelfPlayBenchmarkEngine.BenchmarkMetric
ComparisonOutcome = SelfPlayBenchmarkEngine.ComparisonOutcome
BenchmarkRecord = SelfPlayBenchmarkEngine.Record
BenchmarkAnalysis = SelfPlayBenchmarkEngine.Analysis
BenchmarkReport = SelfPlayBenchmarkEngine.Report
