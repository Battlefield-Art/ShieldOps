"""Access Change Tracker — track access changes."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AccessChangeTracker = engine(
    "AccessChangeTracker",
    description="Track access permission changes.",
    enums={
        "scope": EnumDef(
            "ChangeScope",
            {
                "USER": "user",
                "GROUP": "group",
                "ROLE": "role",
                "SERVICE_ACCOUNT": "service_account",
                "POLICY": "policy",
            },
        ),
        "approval": EnumDef(
            "ApprovalStatus",
            {
                "PENDING": "pending",
                "APPROVED": "approved",
                "DENIED": "denied",
                "AUTO_APPROVED": "auto_approved",
                "EXPIRED": "expired",
            },
        ),
        "impact": EnumDef(
            "ImpactLevel",
            {
                "NONE": "none",
                "LOW": "low",
                "MEDIUM": "medium",
                "HIGH": "high",
                "CRITICAL": "critical",
            },
        ),
    },
    record_fields=[
        FieldDef("change_type", str, ""),
        FieldDef("before_state", str, ""),
        FieldDef("after_state", str, ""),
    ],
    key_field="identity_id",
)

# Backward-compatible re-exports
ChangeScope = AccessChangeTracker.ChangeScope
ApprovalStatus = AccessChangeTracker.ApprovalStatus
ImpactLevel = AccessChangeTracker.ImpactLevel
AccessChangeRecord = AccessChangeTracker.Record
AccessChangeAnalysis = AccessChangeTracker.Analysis
AccessChangeReport = AccessChangeTracker.Report
