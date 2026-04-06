"""Toil Intelligence Engine — toil intelligence with automated detection and reduction."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ToilIntelligenceEngine = engine(
    "ToilIntelligenceEngine",
    description="Toil Intelligence Engine — toil intelligence with automated detection and r...",
    enums={
        "toil_category": EnumDef(
            "ToilCategory",
            {
                "MANUAL_PROCESS": "manual_process",
                "REPETITIVE_TASK": "repetitive_task",
                "INTERRUPT_DRIVEN": "interrupt_driven",
                "SCALING": "scaling",
                "DEPLOYMENT": "deployment",
            },
        ),
        "toil_source": EnumDef(
            "ToilSource",
            {
                "TASK_TRACKING": "task_tracking",
                "RUNBOOK_LOGS": "runbook_logs",
                "ONCALL_DATA": "oncall_data",
                "SURVEY": "survey",
                "AUTOMATED_DETECTION": "automated_detection",
            },
        ),
        "toil_priority": EnumDef(
            "ToilPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "ACCEPTABLE": "acceptable",
            },
        ),
    },
)

# Backward-compatible re-exports
ToilCategory = ToilIntelligenceEngine.ToilCategory
ToilSource = ToilIntelligenceEngine.ToilSource
ToilPriority = ToilIntelligenceEngine.ToilPriority
ToilIntelRecord = ToilIntelligenceEngine.Record
ToilIntelAnalysis = ToilIntelligenceEngine.Analysis
ToilIntelligenceReport = ToilIntelligenceEngine.Report
