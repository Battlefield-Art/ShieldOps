"""Runbook Execution Tracker Engine — track runbook execution outcomes and reliability."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RunbookExecutionTrackerEngine = engine(
    "RunbookExecutionTrackerEngine",
    description="Track runbook execution outcomes and reliability.",
    enums={
        "execution_outcome": EnumDef(
            "ExecutionOutcome",
            {
                "SUCCESS": "success",
                "PARTIAL_SUCCESS": "partial_success",
                "FAILED": "failed",
                "ROLLED_BACK": "rolled_back",
                "TIMED_OUT": "timed_out",
            },
        ),
        "trigger_type": EnumDef(
            "TriggerType",
            {
                "MANUAL": "manual",
                "AUTOMATED": "automated",
                "INCIDENT": "incident",
                "SCHEDULED": "scheduled",
                "ESCALATION": "escalation",
            },
        ),
        "approval_status": EnumDef(
            "ApprovalStatus",
            {
                "AUTO_APPROVED": "auto_approved",
                "MANUALLY_APPROVED": "manually_approved",
                "DENIED": "denied",
                "PENDING": "pending",
                "BYPASSED": "bypassed",
            },
        ),
    },
    record_fields=[
        FieldDef("runbook_name", str, ""),
        FieldDef("duration_min", float, 0.0),
        FieldDef("steps_completed", int, 0),
        FieldDef("rollback_triggered", bool, False),
    ],
    key_field="execution_id",
)

# Backward-compatible re-exports
ExecutionOutcome = RunbookExecutionTrackerEngine.ExecutionOutcome
TriggerType = RunbookExecutionTrackerEngine.TriggerType
ApprovalStatus = RunbookExecutionTrackerEngine.ApprovalStatus
ExecutionRecord = RunbookExecutionTrackerEngine.Record
ExecutionAnalysis = RunbookExecutionTrackerEngine.Analysis
ExecutionReport = RunbookExecutionTrackerEngine.Report
