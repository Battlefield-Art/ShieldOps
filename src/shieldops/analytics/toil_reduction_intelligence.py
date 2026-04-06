"""Toil Reduction Intelligence compute toil reduction trend, detect toil regression, rank team..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ToilReductionIntelligence = engine(
    "ToilReductionIntelligence",
    description="Compute toil reduction trend, detect toil regression, rank teams by toil bu...",
    enums={
        "toil_type": EnumDef(
            "ToilType",
            {
                "MANUAL_OPS": "manual_ops",
                "REPETITIVE_TASK": "repetitive_task",
                "INTERRUPT_DRIVEN": "interrupt_driven",
                "PROCESS_OVERHEAD": "process_overhead",
            },
        ),
        "automation_status": EnumDef(
            "AutomationStatus",
            {
                "AUTOMATED": "automated",
                "PARTIALLY_AUTOMATED": "partially_automated",
                "MANUAL": "manual",
                "PLANNED": "planned",
            },
        ),
        "toil_severity": EnumDef(
            "ToilSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("hours_spent", float, 0.0),
        FieldDef("hours_saved", float, 0.0),
        FieldDef("task_count", int, 0),
        FieldDef("category", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="team_id",
)

# Backward-compatible re-exports
ToilType = ToilReductionIntelligence.ToilType
AutomationStatus = ToilReductionIntelligence.AutomationStatus
ToilSeverity = ToilReductionIntelligence.ToilSeverity
ToilReductionRecord = ToilReductionIntelligence.Record
ToilReductionAnalysis = ToilReductionIntelligence.Analysis
ToilReductionReport = ToilReductionIntelligence.Report
