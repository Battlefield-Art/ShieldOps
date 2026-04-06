"""Reasoning Chain Integrity Engine — validate logical integrity of investigation reasoning ch..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ReasoningChainIntegrityEngine = engine(
    "ReasoningChainIntegrityEngine",
    description="Validate logical integrity of investigation reasoning chains, detect circul...",
    enums={
        "integrity_status": EnumDef(
            "IntegrityStatus",
            {
                "VALID": "valid",
                "WEAK_LINK": "weak_link",
                "BROKEN": "broken",
                "CIRCULAR": "circular",
            },
        ),
        "evidence_strength": EnumDef(
            "EvidenceStrength",
            {
                "CONCLUSIVE": "conclusive",
                "SUPPORTIVE": "supportive",
                "CIRCUMSTANTIAL": "circumstantial",
                "ABSENT": "absent",
            },
        ),
        "violation_type": EnumDef(
            "ViolationType",
            {
                "LOGICAL_GAP": "logical_gap",
                "UNSUPPORTED_LEAP": "unsupported_leap",
                "CIRCULAR_REFERENCE": "circular_reference",
                "CONTRADICTION": "contradiction",
            },
        ),
    },
    record_fields=[
        FieldDef("step_index", int, 0),
        FieldDef("premise", str, ""),
        FieldDef("conclusion", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="confidence_score",
    key_field="chain_id",
)

# Backward-compatible re-exports
IntegrityStatus = ReasoningChainIntegrityEngine.IntegrityStatus
EvidenceStrength = ReasoningChainIntegrityEngine.EvidenceStrength
ViolationType = ReasoningChainIntegrityEngine.ViolationType
ReasoningChainIntegrityRecord = ReasoningChainIntegrityEngine.Record
ReasoningChainIntegrityAnalysis = ReasoningChainIntegrityEngine.Analysis
ReasoningChainIntegrityReport = ReasoningChainIntegrityEngine.Report
