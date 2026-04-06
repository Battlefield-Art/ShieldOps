"""Commitment Utilization Tracker measure commitment utilization, detect underutilized, recomm..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CommitmentUtilizationTracker = engine(
    "CommitmentUtilizationTracker",
    description="Measure commitment utilization, detect underutilized, recommend adjustments.",
    enums={
        "commitment_type": EnumDef(
            "CommitmentType",
            {
                "RESERVED_INSTANCE": "reserved_instance",
                "SAVINGS_PLAN": "savings_plan",
                "CUD": "cud",
                "ENTERPRISE_AGREEMENT": "enterprise_agreement",
            },
        ),
        "utilization_level": EnumDef(
            "UtilizationLevel",
            {
                "OPTIMAL": "optimal",
                "ACCEPTABLE": "acceptable",
                "LOW": "low",
                "CRITICAL": "critical",
            },
        ),
        "adjustment_action": EnumDef(
            "AdjustmentAction",
            {
                "INCREASE": "increase",
                "DECREASE": "decrease",
                "EXCHANGE": "exchange",
                "TERMINATE": "terminate",
            },
        ),
    },
    record_fields=[
        FieldDef("utilization_pct", float, 0.0),
        FieldDef("monthly_commitment", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="commitment_id",
)

# Backward-compatible re-exports
CommitmentType = CommitmentUtilizationTracker.CommitmentType
UtilizationLevel = CommitmentUtilizationTracker.UtilizationLevel
AdjustmentAction = CommitmentUtilizationTracker.AdjustmentAction
CommitmentRecord = CommitmentUtilizationTracker.Record
CommitmentAnalysis = CommitmentUtilizationTracker.Analysis
CommitmentReport = CommitmentUtilizationTracker.Report
