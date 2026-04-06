"""Stakeholder Management Engine — route and track stakeholder comms."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

StakeholderManagementEngine = engine(
    "StakeholderManagementEngine",
    module="operations",  # uses record_item
    description="Route and track stakeholder engagement.",
    enums={
        "category": EnumDef(
            "StakeholderCategory",
            {
                "EXECUTIVE": "executive",
                "TECHNICAL": "technical",
                "LEGAL": "legal",
                "COMMUNICATIONS": "communications",
                "CUSTOMER": "customer",
            },
        ),
        "preference": EnumDef(
            "ContactPreference",
            {
                "SLACK": "slack",
                "EMAIL": "email",
                "PHONE": "phone",
                "SMS": "sms",
                "IN_PERSON": "in_person",
            },
        ),
        "escalation_path": EnumDef(
            "EscalationPath",
            {
                "DIRECT": "direct",
                "MANAGER": "manager",
                "VP": "vp",
                "C_SUITE": "c_suite",
                "BOARD": "board",
            },
        ),
    },
    record_fields=[
        FieldDef("incident_id", str, ""),
        FieldDef("engaged", bool, False),
        FieldDef("response_time_sec", float, 0.0),
    ],
    key_field="stakeholder_name",
)

# Backward-compatible re-exports
StakeholderCategory = StakeholderManagementEngine.StakeholderCategory
ContactPreference = StakeholderManagementEngine.ContactPreference
EscalationPath = StakeholderManagementEngine.EscalationPath
StakeholderRecord = StakeholderManagementEngine.Record
StakeholderAnalysis = StakeholderManagementEngine.Analysis
StakeholderReport = StakeholderManagementEngine.Report
