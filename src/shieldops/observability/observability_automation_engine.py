"""ObservabilityAutomationEngine — automation."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ObservabilityAutomationEngine = engine(
    "ObservabilityAutomationEngine",
    description="Observability Automation Engine. Automates observability responses includin...",
    enums={
        "trigger": EnumDef(
            "AutomationTrigger",
            {
                "THRESHOLD_BREACH": "threshold_breach",
                "ANOMALY_DETECTED": "anomaly_detected",
                "SLO_VIOLATION": "slo_violation",
                "SCHEDULE": "schedule",
            },
        ),
        "action_type": EnumDef(
            "ActionType",
            {
                "ALERT_CREATE": "alert_create",
                "DASHBOARD_UPDATE": "dashboard_update",
                "RULE_MODIFY": "rule_modify",
                "ESCALATE": "escalate",
            },
        ),
        "outcome": EnumDef(
            "AutomationOutcome",
            {
                "SUCCESS": "success",
                "PARTIAL": "partial",
                "FAILED": "failed",
                "SKIPPED": "skipped",
            },
        ),
    },
    record_fields=[
        FieldDef("execution_time_ms", float, 0.0),
        FieldDef("effectiveness", float, 0.0),
    ],
)

# Backward-compatible re-exports
AutomationTrigger = ObservabilityAutomationEngine.AutomationTrigger
ActionType = ObservabilityAutomationEngine.ActionType
AutomationOutcome = ObservabilityAutomationEngine.AutomationOutcome
AutomationRecord = ObservabilityAutomationEngine.Record
AutomationAnalysis = ObservabilityAutomationEngine.Analysis
AutomationReport = ObservabilityAutomationEngine.Report
