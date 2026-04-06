"""Runbook Step Reliability Engine — track individual runbook step reliability."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RunbookStepReliabilityEngine = engine(
    "RunbookStepReliabilityEngine",
    description="Track individual runbook step reliability.",
    enums={
        "step_type": EnumDef(
            "StepType",
            {
                "COMMAND": "command",
                "API_CALL": "api_call",
                "SCRIPT": "script",
                "APPROVAL_GATE": "approval_gate",
                "VERIFICATION": "verification",
                "ROLLBACK": "rollback",
            },
        ),
        "step_outcome": EnumDef(
            "StepOutcome",
            {
                "SUCCESS": "success",
                "FAILED": "failed",
                "TIMEOUT": "timeout",
                "SKIPPED": "skipped",
                "RETRIED": "retried",
            },
        ),
        "failure_category": EnumDef(
            "FailureCategory",
            {
                "PERMISSION": "permission",
                "TIMEOUT": "timeout",
                "DEPENDENCY": "dependency",
                "VALIDATION": "validation",
                "INFRASTRUCTURE": "infrastructure",
            },
        ),
    },
    record_fields=[
        FieldDef("runbook_name", str, ""),
        FieldDef("step_name", str, ""),
        FieldDef("duration_ms", float, 0.0),
        FieldDef("retry_count", int, 0),
    ],
    key_field="step_id",
)

# Backward-compatible re-exports
StepType = RunbookStepReliabilityEngine.StepType
StepOutcome = RunbookStepReliabilityEngine.StepOutcome
FailureCategory = RunbookStepReliabilityEngine.FailureCategory
StepRecord = RunbookStepReliabilityEngine.Record
StepAnalysis = RunbookStepReliabilityEngine.Analysis
StepReport = RunbookStepReliabilityEngine.Report
