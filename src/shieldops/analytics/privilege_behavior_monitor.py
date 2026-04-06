"""Privilege Behavior Monitor — monitor privileged account behaviors and detect abuse."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PrivilegeBehaviorMonitor = engine(
    "PrivilegeBehaviorMonitor",
    description="Monitor privileged account behaviors, detect escalation, and track abuse pa...",
    enums={
        "privilege_type": EnumDef(
            "PrivilegeType",
            {
                "ADMIN": "admin",
                "ROOT": "root",
                "SERVICE_ACCOUNT": "service_account",
                "ELEVATED": "elevated",
                "STANDARD": "standard",
            },
        ),
        "behavior_pattern": EnumDef(
            "BehaviorPattern",
            {
                "NORMAL_USE": "normal_use",
                "PRIVILEGE_ESCALATION": "privilege_escalation",
                "LATERAL_MOVEMENT": "lateral_movement",
                "DATA_HOARDING": "data_hoarding",
                "POLICY_BYPASS": "policy_bypass",
            },
        ),
        "monitoring_status": EnumDef(
            "MonitoringStatus",
            {
                "ACTIVE": "active",
                "ALERTING": "alerting",
                "INVESTIGATING": "investigating",
                "RESOLVED": "resolved",
                "BASELINE": "baseline",
            },
        ),
    },
    score_field="risk_score",
    key_field="account_name",
)

# Backward-compatible re-exports
PrivilegeType = PrivilegeBehaviorMonitor.PrivilegeType
BehaviorPattern = PrivilegeBehaviorMonitor.BehaviorPattern
MonitoringStatus = PrivilegeBehaviorMonitor.MonitoringStatus
PrivilegeRecord = PrivilegeBehaviorMonitor.Record
PrivilegeAnalysis = PrivilegeBehaviorMonitor.Analysis
PrivilegeBehaviorReport = PrivilegeBehaviorMonitor.Report
