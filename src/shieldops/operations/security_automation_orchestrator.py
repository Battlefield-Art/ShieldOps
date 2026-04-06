"""SecurityAutomationOrchestrator — security automation orchestrator."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SecurityAutomationOrchestrator = engine(
    "SecurityAutomationOrchestrator",
    module="operations",  # uses record_item
    description="Security Automation Orchestrator.",
    enums={
        "automation_type": EnumDef(
            "AutomationType",
            {
                "RESPONSE": "response",
                "INVESTIGATION": "investigation",
                "REMEDIATION": "remediation",
                "REPORTING": "reporting",
                "COMPLIANCE": "compliance",
            },
        ),
        "orchestration_type": EnumDef(
            "OrchestrationType",
            {
                "SEQUENTIAL": "sequential",
                "PARALLEL": "parallel",
                "CONDITIONAL": "conditional",
                "LOOP": "loop",
                "HYBRID": "hybrid",
            },
        ),
        "execution_status": EnumDef(
            "ExecutionStatus",
            {
                "RUNNING": "running",
                "COMPLETED": "completed",
                "FAILED": "failed",
                "PAUSED": "paused",
                "CANCELLED": "cancelled",
            },
        ),
    },
)

# Backward-compatible re-exports
AutomationType = SecurityAutomationOrchestrator.AutomationType
OrchestrationType = SecurityAutomationOrchestrator.OrchestrationType
ExecutionStatus = SecurityAutomationOrchestrator.ExecutionStatus
SecurityAutomationOrchestratorRecord = SecurityAutomationOrchestrator.Record
SecurityAutomationOrchestratorAnalysis = SecurityAutomationOrchestrator.Analysis
SecurityAutomationOrchestratorReport = SecurityAutomationOrchestrator.Report
