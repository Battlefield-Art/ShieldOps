"""AgentCapabilityTracker — tracks AI agent capability registrations and boundary violations."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AgentCapabilityTracker = engine(
    "AgentCapabilityTracker",
    description="Tracks AI agent capability registrations and boundary violations.",
    enums={
        "scope": EnumDef(
            "CapabilityScope",
            {
                "READ_ONLY": "read_only",
                "READ_WRITE": "read_write",
                "ADMIN": "admin",
                "UNRESTRICTED": "unrestricted",
            },
        ),
        "boundary_status": EnumDef(
            "BoundaryStatus",
            {
                "WITHIN": "within",
                "NEAR_LIMIT": "near_limit",
                "EXCEEDED": "exceeded",
                "BLOCKED": "blocked",
            },
        ),
        "governance_action": EnumDef(
            "GovernanceAction",
            {
                "APPROVE": "approve",
                "RESTRICT": "restrict",
                "REVOKE": "revoke",
                "AUDIT": "audit",
            },
        ),
    },
    record_fields=[
        FieldDef("capability", str, ""),
        FieldDef("resource_target", str, ""),
        FieldDef("invocation_count", int, 0),
        FieldDef("max_invocations", int, 1000),
        FieldDef("metadata", dict, ""),
    ],
    score_field="risk_score",
    key_field="agent_id",
)

# Backward-compatible re-exports
CapabilityScope = AgentCapabilityTracker.CapabilityScope
BoundaryStatus = AgentCapabilityTracker.BoundaryStatus
GovernanceAction = AgentCapabilityTracker.GovernanceAction
CapabilityRecord = AgentCapabilityTracker.Record
CapabilityAnalysis = AgentCapabilityTracker.Analysis
CapabilityReport = AgentCapabilityTracker.Report
