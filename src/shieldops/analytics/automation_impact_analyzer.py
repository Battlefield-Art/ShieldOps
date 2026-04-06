"""Automation Impact Analyzer — automation impact analysis and ROI measurement."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutomationImpactAnalyzer = engine(
    "AutomationImpactAnalyzer",
    description="Automation Impact Analyzer — automation impact analysis and ROI measurement.",
    enums={
        "automation_type": EnumDef(
            "AutomationType",
            {
                "RUNBOOK": "runbook",
                "SCALING": "scaling",
                "REMEDIATION": "remediation",
                "DEPLOYMENT": "deployment",
                "SECURITY": "security",
            },
        ),
        "impact_metric": EnumDef(
            "ImpactMetric",
            {
                "TIME_SAVED": "time_saved",
                "INCIDENTS_PREVENTED": "incidents_prevented",
                "COST_REDUCTION": "cost_reduction",
                "MTTR_IMPROVEMENT": "mttr_improvement",
                "TOIL_REDUCTION": "toil_reduction",
            },
        ),
        "impact_level": EnumDef(
            "ImpactLevel",
            {
                "TRANSFORMATIVE": "transformative",
                "SIGNIFICANT": "significant",
                "MODERATE": "moderate",
                "MARGINAL": "marginal",
                "NEGLIGIBLE": "negligible",
            },
        ),
    },
)

# Backward-compatible re-exports
AutomationType = AutomationImpactAnalyzer.AutomationType
ImpactMetric = AutomationImpactAnalyzer.ImpactMetric
ImpactLevel = AutomationImpactAnalyzer.ImpactLevel
ImpactRecord = AutomationImpactAnalyzer.Record
ImpactAnalysis = AutomationImpactAnalyzer.Analysis
AutomationImpactReport = AutomationImpactAnalyzer.Report
