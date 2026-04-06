"""Mitigation Efficacy Tracker — compute mitigation success rate, detect ineffective mitigatio..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MitigationEfficacyTracker = engine(
    "MitigationEfficacyTracker",
    description="Compute mitigation success rate, detect ineffective mitigations, rank strat...",
    enums={
        "mitigation_result": EnumDef(
            "MitigationResult",
            {
                "EFFECTIVE": "effective",
                "PARTIALLY_EFFECTIVE": "partially_effective",
                "INEFFECTIVE": "ineffective",
                "COUNTERPRODUCTIVE": "counterproductive",
            },
        ),
        "mitigation_type": EnumDef(
            "MitigationType",
            {
                "AUTOMATED": "automated",
                "MANUAL": "manual",
                "HYBRID": "hybrid",
                "ESCALATION": "escalation",
            },
        ),
        "efficacy_level": EnumDef(
            "EfficacyLevel",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "NONE": "none",
            },
        ),
    },
    record_fields=[
        FieldDef("strategy_name", str, ""),
        FieldDef("time_to_mitigate_seconds", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="efficacy_score",
    key_field="incident_id",
)

# Backward-compatible re-exports
MitigationResult = MitigationEfficacyTracker.MitigationResult
MitigationType = MitigationEfficacyTracker.MitigationType
EfficacyLevel = MitigationEfficacyTracker.EfficacyLevel
MitigationEfficacyRecord = MitigationEfficacyTracker.Record
MitigationEfficacyAnalysis = MitigationEfficacyTracker.Analysis
MitigationEfficacyReport = MitigationEfficacyTracker.Report
