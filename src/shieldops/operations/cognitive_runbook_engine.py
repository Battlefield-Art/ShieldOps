"""Cognitive Runbook Engine Self-evolving runbook system that learns from execution outcomes a..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CognitiveRunbookEngine = engine(
    "CognitiveRunbookEngine",
    description="Cognitive Runbook Engine Self-evolving runbook system that learns from exec...",
    enums={
        "outcome": EnumDef(
            "RunbookOutcome",
            {
                "SUCCESS": "success",
                "PARTIAL_SUCCESS": "partial_success",
                "FAILURE": "failure",
                "SKIPPED": "skipped",
                "TIMEOUT": "timeout",
            },
        ),
        "learning_signal": EnumDef(
            "LearningSignal",
            {
                "POSITIVE": "positive",
                "NEGATIVE": "negative",
                "NEUTRAL": "neutral",
                "AMBIGUOUS": "ambiguous",
            },
        ),
        "evolution_action": EnumDef(
            "EvolutionAction",
            {
                "ADD_STEP": "add_step",
                "REMOVE_STEP": "remove_step",
                "MODIFY_STEP": "modify_step",
                "REORDER": "reorder",
                "SPLIT": "split",
            },
        ),
    },
    record_fields=[
        FieldDef("step_name", str, ""),
        FieldDef("execution_time_sec", float, 0.0),
        FieldDef("operator", str, ""),
    ],
    key_field="runbook_id",
)

# Backward-compatible re-exports
RunbookOutcome = CognitiveRunbookEngine.RunbookOutcome
LearningSignal = CognitiveRunbookEngine.LearningSignal
EvolutionAction = CognitiveRunbookEngine.EvolutionAction
RunbookRecord = CognitiveRunbookEngine.Record
RunbookAnalysis = CognitiveRunbookEngine.Analysis
RunbookReport = CognitiveRunbookEngine.Report
