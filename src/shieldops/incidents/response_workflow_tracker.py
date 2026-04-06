"""Response Workflow Tracker — track incident response workflow phases and status."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ResponseWorkflowTracker = engine(
    "ResponseWorkflowTracker",
    description="Track incident response workflows — phases and completion.",
    enums={
        "workflow_phase": EnumDef(
            "WorkflowPhase",
            {
                "DETECTION": "detection",
                "CONTAINMENT": "containment",
                "ERADICATION": "eradication",
                "RECOVERY": "recovery",
                "LESSONS_LEARNED": "lessons_learned",
            },
        ),
        "workflow_status": EnumDef(
            "WorkflowStatus",
            {
                "ACTIVE": "active",
                "PAUSED": "paused",
                "COMPLETED": "completed",
                "ESCALATED": "escalated",
                "CANCELLED": "cancelled",
            },
        ),
        "workflow_priority": EnumDef(
            "WorkflowPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "ROUTINE": "routine",
            },
        ),
    },
)

# Backward-compatible re-exports
WorkflowPhase = ResponseWorkflowTracker.WorkflowPhase
WorkflowStatus = ResponseWorkflowTracker.WorkflowStatus
WorkflowPriority = ResponseWorkflowTracker.WorkflowPriority
WorkflowRecord = ResponseWorkflowTracker.Record
WorkflowAnalysis = ResponseWorkflowTracker.Analysis
WorkflowReport = ResponseWorkflowTracker.Report
