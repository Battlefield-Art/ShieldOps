"""Automated Policy Enforcer — enforce policies with automated actions."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutomatedPolicyEnforcer = engine(
    "AutomatedPolicyEnforcer",
    description="Enforce policies with automated actions, track violations, analyze enforcem...",
    enums={
        "enforcement_action": EnumDef(
            "EnforcementAction",
            {
                "BLOCK": "block",
                "ALERT": "alert",
                "REMEDIATE": "remediate",
                "AUDIT": "audit",
                "EXEMPT": "exempt",
            },
        ),
        "enforcement_scope": EnumDef(
            "EnforcementScope",
            {
                "REALTIME": "realtime",
                "SCHEDULED": "scheduled",
                "ON_DEMAND": "on_demand",
                "CONTINUOUS": "continuous",
                "EVENT_DRIVEN": "event_driven",
            },
        ),
        "violation_severity": EnumDef(
            "ViolationSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFORMATIONAL": "informational",
            },
        ),
    },
    score_field="enforcement_score",
    key_field="policy_name",
)

# Backward-compatible re-exports
EnforcementAction = AutomatedPolicyEnforcer.EnforcementAction
EnforcementScope = AutomatedPolicyEnforcer.EnforcementScope
ViolationSeverity = AutomatedPolicyEnforcer.ViolationSeverity
EnforcementRecord = AutomatedPolicyEnforcer.Record
EnforcementAnalysis = AutomatedPolicyEnforcer.Analysis
EnforcementReport = AutomatedPolicyEnforcer.Report
