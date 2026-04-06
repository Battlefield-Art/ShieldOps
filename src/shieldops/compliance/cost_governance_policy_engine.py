"""Cost Governance Policy Engine enforce budget gates, evaluate policy compliance, detect poli..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CostGovernancePolicyEngine = engine(
    "CostGovernancePolicyEngine",
    description="Enforce budget gates, evaluate compliance, detect policy violations.",
    enums={
        "policy_type": EnumDef(
            "PolicyType",
            {
                "BUDGET_GATE": "budget_gate",
                "APPROVAL_THRESHOLD": "approval_threshold",
                "PROVISIONING_GUARD": "provisioning_guard",
                "TAG_ENFORCEMENT": "tag_enforcement",
            },
        ),
        "compliance_status": EnumDef(
            "ComplianceStatus",
            {
                "COMPLIANT": "compliant",
                "WARNING": "warning",
                "VIOLATION": "violation",
                "EXEMPT": "exempt",
            },
        ),
        "enforcement_level": EnumDef(
            "EnforcementLevel",
            {
                "BLOCKING": "blocking",
                "ADVISORY": "advisory",
                "LOGGING": "logging",
                "DISABLED": "disabled",
            },
        ),
    },
    record_fields=[
        FieldDef("budget_amount", float, 0.0),
        FieldDef("actual_amount", float, 0.0),
        FieldDef("team_id", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="policy_id",
)

# Backward-compatible re-exports
PolicyType = CostGovernancePolicyEngine.PolicyType
ComplianceStatus = CostGovernancePolicyEngine.ComplianceStatus
EnforcementLevel = CostGovernancePolicyEngine.EnforcementLevel
GovernanceRecord = CostGovernancePolicyEngine.Record
GovernanceAnalysis = CostGovernancePolicyEngine.Analysis
GovernanceReport = CostGovernancePolicyEngine.Report
