"""TicketAutomationEngine — automate ticket ops."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TicketAutomationEngine = engine(
    "TicketAutomationEngine",
    module="operations",  # uses record_item
    description="Automate ticket lifecycle operations.",
    enums={
        "ticket_action": EnumDef(
            "TicketAction",
            {
                "CREATE": "create",
                "UPDATE": "update",
                "ESCALATE": "escalate",
                "CLOSE": "close",
                "REOPEN": "reopen",
            },
        ),
        "routing_rule": EnumDef(
            "RoutingRule",
            {
                "SEVERITY_BASED": "severity_based",
                "TEAM_BASED": "team_based",
                "ROUND_ROBIN": "round_robin",
                "SKILL_MATCH": "skill_match",
            },
        ),
        "closure_reason": EnumDef(
            "ClosureReason",
            {
                "RESOLVED": "resolved",
                "DUPLICATE": "duplicate",
                "FALSE_POSITIVE": "false_positive",
                "ACCEPTED_RISK": "accepted_risk",
                "AUTO_VERIFIED": "auto_verified",
            },
        ),
    },
    record_fields=[
        FieldDef("ticket_id", str, ""),
        FieldDef("assigned_team", str, ""),
        FieldDef("finding_id", str, ""),
        FieldDef("entity", str, ""),
    ],
)

# Backward-compatible re-exports
TicketAction = TicketAutomationEngine.TicketAction
RoutingRule = TicketAutomationEngine.RoutingRule
ClosureReason = TicketAutomationEngine.ClosureReason
TicketAutomationRecord = TicketAutomationEngine.Record
TicketAutomationAnalysis = TicketAutomationEngine.Analysis
TicketAutomationReport = TicketAutomationEngine.Report
