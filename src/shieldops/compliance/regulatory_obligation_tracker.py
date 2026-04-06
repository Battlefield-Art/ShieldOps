"""Regulatory Obligation Tracker compute obligation completion rate, detect approaching deadli..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RegulatoryObligationTracker = engine(
    "RegulatoryObligationTracker",
    description="Compute obligation completion rate, detect approaching deadlines, rank obli...",
    enums={
        "obligation_status": EnumDef(
            "ObligationStatus",
            {
                "COMPLIANT": "compliant",
                "AT_RISK": "at_risk",
                "NON_COMPLIANT": "non_compliant",
                "EXEMPT": "exempt",
            },
        ),
        "obligation_type": EnumDef(
            "ObligationType",
            {
                "REPORTING": "reporting",
                "CERTIFICATION": "certification",
                "ASSESSMENT": "assessment",
                "DISCLOSURE": "disclosure",
            },
        ),
        "penalty_risk": EnumDef(
            "PenaltyRisk",
            {
                "SEVERE": "severe",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("completion_rate", float, 0.0),
        FieldDef("days_to_deadline", float, 30.0),
        FieldDef("penalty_amount", float, 0.0),
        FieldDef("regulation", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="obligation_id",
)

# Backward-compatible re-exports
ObligationStatus = RegulatoryObligationTracker.ObligationStatus
ObligationType = RegulatoryObligationTracker.ObligationType
PenaltyRisk = RegulatoryObligationTracker.PenaltyRisk
ObligationRecord = RegulatoryObligationTracker.Record
ObligationAnalysis = RegulatoryObligationTracker.Analysis
ObligationReport = RegulatoryObligationTracker.Report
