"""SLAEnforcementEngine — monitor and enforce SLAs."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SLAEnforcementEngine = engine(
    "SLAEnforcementEngine",
    module="operations",  # uses record_item
    description="Monitor and enforce SLA compliance.",
    enums={
        "sla_tier": EnumDef(
            "SLATier",
            {
                "PLATINUM": "platinum",
                "GOLD": "gold",
                "SILVER": "silver",
                "BRONZE": "bronze",
            },
        ),
        "escalation_step": EnumDef(
            "EscalationStep",
            {
                "NONE": "none",
                "NOTIFY": "notify",
                "ESCALATE_L1": "escalate_l1",
                "ESCALATE_L2": "escalate_l2",
                "EXECUTIVE": "executive",
            },
        ),
        "breach_consequence": EnumDef(
            "BreachConsequence",
            {
                "WARNING": "warning",
                "CREDIT": "credit",
                "PENALTY": "penalty",
                "CONTRACT_REVIEW": "contract_review",
            },
        ),
    },
    record_fields=[
        FieldDef("target_hours", float, 24.0),
        FieldDef("elapsed_hours", float, 0.0),
        FieldDef("breached", bool, False),
        FieldDef("entity", str, ""),
    ],
)

# Backward-compatible re-exports
SLATier = SLAEnforcementEngine.SLATier
EscalationStep = SLAEnforcementEngine.EscalationStep
BreachConsequence = SLAEnforcementEngine.BreachConsequence
SLAEnforcementRecord = SLAEnforcementEngine.Record
SLAEnforcementAnalysis = SLAEnforcementEngine.Analysis
SLAEnforcementReport = SLAEnforcementEngine.Report
