"""Proposer Solver Coevolution Engine — manages the co-evolution feedback loop between propose..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ProposerSolverCoevolutionEngine = engine(
    "ProposerSolverCoevolutionEngine",
    description="Manages the co-evolution feedback loop between proposer and solver.",
    enums={
        "state": EnumDef(
            "CoevolutionState",
            {
                "INITIALIZING": "initializing",
                "EVOLVING": "evolving",
                "CONVERGING": "converging",
                "CONVERGED": "converged",
            },
        ),
        "feedback_direction": EnumDef(
            "FeedbackDirection",
            {
                "PROPOSER_TO_SOLVER": "proposer_to_solver",
                "SOLVER_TO_PROPOSER": "solver_to_proposer",
                "BIDIRECTIONAL": "bidirectional",
                "STALLED": "stalled",
            },
        ),
        "outcome": EnumDef(
            "IterationOutcome",
            {
                "SOLVER_IMPROVED": "solver_improved",
                "PROPOSER_ADAPTED": "proposer_adapted",
                "BOTH_IMPROVED": "both_improved",
                "NO_CHANGE": "no_change",
            },
        ),
    },
    record_fields=[
        FieldDef("iteration", int, 0),
        FieldDef("solver_delta", float, 0.0),
        FieldDef("proposer_delta", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="efficiency_score",
    key_field="coevolution_id",
)

# Backward-compatible re-exports
CoevolutionState = ProposerSolverCoevolutionEngine.CoevolutionState
FeedbackDirection = ProposerSolverCoevolutionEngine.FeedbackDirection
IterationOutcome = ProposerSolverCoevolutionEngine.IterationOutcome
CoevolutionRecord = ProposerSolverCoevolutionEngine.Record
CoevolutionAnalysis = ProposerSolverCoevolutionEngine.Analysis
CoevolutionReport = ProposerSolverCoevolutionEngine.Report
