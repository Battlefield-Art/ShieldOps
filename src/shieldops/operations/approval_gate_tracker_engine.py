"""ApprovalGateTrackerEngine — Track and analyze approval gate decisions."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ApprovalGateTrackerEngine = engine(
    "ApprovalGateTrackerEngine",
    description="Track and analyze approval gate decisions and wait times.",
    enums={
        "gate_type": EnumDef(
            "GateType",
            {
                "MANUAL_APPROVAL": "manual_approval",
                "POLICY_CHECK": "policy_check",
                "SLO_GUARD": "slo_guard",
                "CHANGE_WINDOW": "change_window",
                "BLAST_RADIUS": "blast_radius",
            },
        ),
        "approval_outcome": EnumDef(
            "ApprovalOutcome",
            {
                "APPROVED": "approved",
                "DENIED": "denied",
                "TIMEOUT": "timeout",
                "AUTO_APPROVED": "auto_approved",
                "ESCALATED": "escalated",
            },
        ),
        "wait_category": EnumDef(
            "WaitCategory",
            {
                "UNDER_1H": "under_1h",
                "UNDER_4H": "under_4h",
                "UNDER_24H": "under_24h",
                "OVER_24H": "over_24h",
                "INSTANT": "instant",
            },
        ),
    },
    record_fields=[
        FieldDef("wait_seconds", float, 0.0),
        FieldDef("approver", str, ""),
        FieldDef("requester", str, ""),
    ],
)

# Backward-compatible re-exports
GateType = ApprovalGateTrackerEngine.GateType
ApprovalOutcome = ApprovalGateTrackerEngine.ApprovalOutcome
WaitCategory = ApprovalGateTrackerEngine.WaitCategory
ApprovalGateTrackerRecord = ApprovalGateTrackerEngine.Record
ApprovalGateTrackerAnalysis = ApprovalGateTrackerEngine.Analysis
ApprovalGateTrackerReport = ApprovalGateTrackerEngine.Report
