"""Hypothesis Experiment Loop Engine — advance loop phases, evaluate evidence, and select the..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

HypothesisExperimentLoopEngine = engine(
    "HypothesisExperimentLoopEngine",
    description="Advance loop phases, evaluate hypothesis evidence, and select next hypothes...",
    enums={
        "phase": EnumDef(
            "LoopPhase",
            {
                "HYPOTHESIS": "hypothesis",
                "EXPERIMENT": "experiment",
                "EVALUATE": "evaluate",
                "ITERATE": "iterate",
            },
        ),
        "status": EnumDef(
            "HypothesisStatus",
            {
                "PROPOSED": "proposed",
                "TESTING": "testing",
                "CONFIRMED": "confirmed",
                "REJECTED": "rejected",
            },
        ),
        "outcome": EnumDef(
            "ExperimentOutcome",
            {
                "IMPROVEMENT": "improvement",
                "NO_CHANGE": "no_change",
                "REGRESSION": "regression",
                "INCONCLUSIVE": "inconclusive",
            },
        ),
    },
    record_fields=[
        FieldDef("confidence", float, 0.0),
        FieldDef("improvement_delta", float, 0.0),
        FieldDef("iterations", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="hypothesis_id",
)

# Backward-compatible re-exports
LoopPhase = HypothesisExperimentLoopEngine.LoopPhase
HypothesisStatus = HypothesisExperimentLoopEngine.HypothesisStatus
ExperimentOutcome = HypothesisExperimentLoopEngine.ExperimentOutcome
HypothesisExperimentRecord = HypothesisExperimentLoopEngine.Record
HypothesisExperimentAnalysis = HypothesisExperimentLoopEngine.Analysis
HypothesisExperimentReport = HypothesisExperimentLoopEngine.Report
