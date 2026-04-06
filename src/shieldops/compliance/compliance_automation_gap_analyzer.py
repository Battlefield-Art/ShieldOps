"""Compliance Automation Gap Analyzer compute automation potential, detect manual bottlenecks,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ComplianceAutomationGapAnalyzer = engine(
    "ComplianceAutomationGapAnalyzer",
    description="Compute automation potential, detect manual bottlenecks, rank controls by a...",
    enums={
        "automation_level": EnumDef(
            "AutomationLevel",
            {
                "FULLY_AUTOMATED": "fully_automated",
                "SEMI_AUTOMATED": "semi_automated",
                "MANUAL": "manual",
                "NOT_APPLICABLE": "not_applicable",
            },
        ),
        "gap_type": EnumDef(
            "GapType",
            {
                "TOOLING": "tooling",
                "INTEGRATION": "integration",
                "PROCESS": "process",
                "SKILL": "skill",
            },
        ),
        "roi_category": EnumDef(
            "RoiCategory",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "NEGATIVE": "negative",
            },
        ),
    },
    record_fields=[
        FieldDef("automation_potential", float, 0.0),
        FieldDef("manual_hours", float, 0.0),
        FieldDef("estimated_savings", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="control_id",
)

# Backward-compatible re-exports
AutomationLevel = ComplianceAutomationGapAnalyzer.AutomationLevel
GapType = ComplianceAutomationGapAnalyzer.GapType
RoiCategory = ComplianceAutomationGapAnalyzer.RoiCategory
AutomationGapRecord = ComplianceAutomationGapAnalyzer.Record
AutomationGapAnalysis = ComplianceAutomationGapAnalyzer.Analysis
AutomationGapReport = ComplianceAutomationGapAnalyzer.Report
