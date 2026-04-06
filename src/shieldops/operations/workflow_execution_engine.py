"""WorkflowExecutionEngine — Track and analyze automated workflow executions."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

WorkflowExecutionEngine = engine(
    "WorkflowExecutionEngine",
    description="Track and analyze automated workflow executions.",
    enums={
        "workflow_type": EnumDef(
            "WorkflowType",
            {
                "INCIDENT_RESPONSE": "incident_response",
                "ACCESS_REVOCATION": "access_revocation",
                "COMPLIANCE_SCAN": "compliance_scan",
                "THREAT_HUNT": "threat_hunt",
                "CHANGE_APPROVAL": "change_approval",
            },
        ),
        "execution_status": EnumDef(
            "ExecutionStatus",
            {
                "SUCCESS": "success",
                "FAILED": "failed",
                "PAUSED": "paused",
                "CANCELLED": "cancelled",
                "TIMEOUT": "timeout",
            },
        ),
        "gate_decision": EnumDef(
            "GateDecision",
            {
                "APPROVED": "approved",
                "DENIED": "denied",
                "PENDING": "pending",
                "AUTO_APPROVED": "auto_approved",
                "ESCALATED": "escalated",
            },
        ),
    },
    record_fields=[
        FieldDef("duration_seconds", float, 0.0),
        FieldDef("step_count", int, 0),
        FieldDef("failed_step", str, ""),
    ],
)

# Backward-compatible re-exports
WorkflowType = WorkflowExecutionEngine.WorkflowType
ExecutionStatus = WorkflowExecutionEngine.ExecutionStatus
GateDecision = WorkflowExecutionEngine.GateDecision
WorkflowExecutionRecord = WorkflowExecutionEngine.Record
WorkflowExecutionAnalysis = WorkflowExecutionEngine.Analysis
WorkflowExecutionReport = WorkflowExecutionEngine.Report
