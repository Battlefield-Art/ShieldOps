"""FindingLifecycleEngine — Track finding lifecycle."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

FindingLifecycleEngine = engine(
    "FindingLifecycleEngine",
    module="operations",  # uses record_item
    description="Track security finding lifecycle and SLA.",
    enums={
        "state": EnumDef(
            "FindingState",
            {
                "NEW": "new",
                "TRIAGED": "triaged",
                "IN_PROGRESS": "in_progress",
                "REMEDIATED": "remediated",
                "VERIFIED": "verified",
                "CLOSED": "closed",
                "REOPENED": "reopened",
            },
        ),
        "sla": EnumDef(
            "SLACompliance",
            {
                "WITHIN_SLA": "within_sla",
                "WARNING": "warning",
                "BREACHED": "breached",
                "NOT_APPLICABLE": "not_applicable",
            },
        ),
        "verification": EnumDef(
            "VerificationStatus",
            {
                "PENDING": "pending",
                "PASS": "pass",
                "FAIL": "fail",
                "PARTIAL": "partial",
                "SKIPPED": "skipped",
            },
        ),
    },
    record_fields=[
        FieldDef("age_days", float, 0.0),
        FieldDef("sla_deadline_epoch", float, 0.0),
    ],
    key_field="finding_id",
)

# Backward-compatible re-exports
FindingState = FindingLifecycleEngine.FindingState
SLACompliance = FindingLifecycleEngine.SLACompliance
VerificationStatus = FindingLifecycleEngine.VerificationStatus
FindingLifecycleRecord = FindingLifecycleEngine.Record
FindingLifecycleAnalysis = FindingLifecycleEngine.Analysis
FindingLifecycleReport = FindingLifecycleEngine.Report
