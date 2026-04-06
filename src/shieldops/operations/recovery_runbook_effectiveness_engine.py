"""Recovery Runbook Effectiveness Engine — compute runbook success rate, detect runbook gaps,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RecoveryRunbookEffectivenessEngine = engine(
    "RecoveryRunbookEffectivenessEngine",
    module="operations",  # uses record_item
    description="Compute runbook success rate, detect runbook gaps, rank runbooks by recover...",
    enums={
        "runbook_outcome": EnumDef(
            "RunbookOutcome",
            {
                "SUCCESS": "success",
                "PARTIAL": "partial",
                "FAILURE": "failure",
                "SKIPPED": "skipped",
            },
        ),
        "runbook_type": EnumDef(
            "RunbookType",
            {
                "AUTOMATED": "automated",
                "SEMI_AUTOMATED": "semi_automated",
                "MANUAL": "manual",
                "HYBRID": "hybrid",
            },
        ),
        "effectiveness_level": EnumDef(
            "EffectivenessLevel",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
            },
        ),
    },
    record_fields=[
        FieldDef("runbook_id", str, ""),
        FieldDef("recovery_time_seconds", float, 0.0),
    ],
)

# Backward-compatible re-exports
RunbookOutcome = RecoveryRunbookEffectivenessEngine.RunbookOutcome
RunbookType = RecoveryRunbookEffectivenessEngine.RunbookType
EffectivenessLevel = RecoveryRunbookEffectivenessEngine.EffectivenessLevel
RunbookEffectivenessRecord = RecoveryRunbookEffectivenessEngine.Record
RunbookEffectivenessAnalysis = RecoveryRunbookEffectivenessEngine.Analysis
RunbookEffectivenessReport = RecoveryRunbookEffectivenessEngine.Report
