"""Security Policy Lifecycle — manage policy phases from draft to retirement."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SecurityPolicyLifecycle = engine(
    "SecurityPolicyLifecycle",
    description="Track security policy phases from draft to retirement, compliance scoring,...",
    enums={
        "policy_phase": EnumDef(
            "PolicyPhase",
            {
                "DRAFT": "draft",
                "REVIEW": "review",
                "APPROVED": "approved",
                "ENFORCED": "enforced",
                "RETIRED": "retired",
            },
        ),
        "policy_category": EnumDef(
            "PolicyCategory",
            {
                "ACCESS_CONTROL": "access_control",
                "DATA_PROTECTION": "data_protection",
                "NETWORK_SECURITY": "network_security",
                "INCIDENT_RESPONSE": "incident_response",
                "COMPLIANCE": "compliance",
            },
        ),
        "policy_scope": EnumDef(
            "PolicyScope",
            {
                "ORGANIZATION": "organization",
                "DEPARTMENT": "department",
                "TEAM": "team",
                "APPLICATION": "application",
                "INFRASTRUCTURE": "infrastructure",
            },
        ),
    },
    score_field="compliance_score",
    key_field="policy_name",
)

# Backward-compatible re-exports
PolicyPhase = SecurityPolicyLifecycle.PolicyPhase
PolicyCategory = SecurityPolicyLifecycle.PolicyCategory
PolicyScope = SecurityPolicyLifecycle.PolicyScope
PolicyRecord = SecurityPolicyLifecycle.Record
PolicyAnalysis = SecurityPolicyLifecycle.Analysis
PolicyLifecycleReport = SecurityPolicyLifecycle.Report
