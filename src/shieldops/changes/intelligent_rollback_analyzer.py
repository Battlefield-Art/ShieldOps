"""Intelligent Rollback Analyzer — intelligent rollback analysis with risk assessment."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

IntelligentRollbackAnalyzer = engine(
    "IntelligentRollbackAnalyzer",
    description="Intelligent Rollback Analyzer — intelligent rollback analysis with risk ass...",
    enums={
        "rollback_type": EnumDef(
            "RollbackType",
            {
                "FULL": "full",
                "PARTIAL": "partial",
                "CANARY": "canary",
                "BLUE_GREEN": "blue_green",
                "FEATURE_FLAG": "feature_flag",
            },
        ),
        "rollback_trigger": EnumDef(
            "RollbackTrigger",
            {
                "ERROR_RATE": "error_rate",
                "LATENCY": "latency",
                "HEALTH_CHECK": "health_check",
                "MANUAL": "manual",
                "AUTOMATED": "automated",
            },
        ),
        "rollback_risk": EnumDef(
            "RollbackRisk",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "SAFE": "safe",
            },
        ),
    },
)

# Backward-compatible re-exports
RollbackType = IntelligentRollbackAnalyzer.RollbackType
RollbackTrigger = IntelligentRollbackAnalyzer.RollbackTrigger
RollbackRisk = IntelligentRollbackAnalyzer.RollbackRisk
RollbackRecord = IntelligentRollbackAnalyzer.Record
RollbackAnalysis = IntelligentRollbackAnalyzer.Analysis
IntelligentRollbackReport = IntelligentRollbackAnalyzer.Report
