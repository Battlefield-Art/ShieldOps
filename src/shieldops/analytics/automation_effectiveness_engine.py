"""Automation Effectiveness Engine — automation ROI and effectiveness analysis."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutomationEffectivenessEngine = engine(
    "AutomationEffectivenessEngine",
    description="Automation Effectiveness Engine for automation ROI and effectiveness analysis.",
    enums={
        "automation_type": EnumDef(
            "AutomationType",
            {
                "RUNBOOK": "runbook",
                "POLICY": "policy",
                "WORKFLOW": "workflow",
                "SELF_HEALING": "self_healing",
            },
        ),
        "effectiveness_metric": EnumDef(
            "EffectivenessMetric",
            {
                "SUCCESS_RATE": "success_rate",
                "TIME_SAVED": "time_saved",
                "ERROR_REDUCTION": "error_reduction",
                "COST_SAVINGS": "cost_savings",
            },
        ),
        "maturity_level": EnumDef(
            "MaturityLevel",
            {
                "MANUAL": "manual",
                "SCRIPTED": "scripted",
                "AUTOMATED": "automated",
                "AUTONOMOUS": "autonomous",
            },
        ),
    },
)

# Backward-compatible re-exports
AutomationType = AutomationEffectivenessEngine.AutomationType
EffectivenessMetric = AutomationEffectivenessEngine.EffectivenessMetric
MaturityLevel = AutomationEffectivenessEngine.MaturityLevel
EffectivenessRecord = AutomationEffectivenessEngine.Record
EffectivenessAnalysis = AutomationEffectivenessEngine.Analysis
AutomationEffectivenessReport = AutomationEffectivenessEngine.Report
