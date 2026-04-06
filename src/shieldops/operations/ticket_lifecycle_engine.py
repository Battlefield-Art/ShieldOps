"""Ticket Lifecycle Engine — track ticket flow."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TicketLifecycleEngine = engine(
    "TicketLifecycleEngine",
    module="operations",  # uses record_item
    description="Track ticket lifecycle and routing.",
    enums={
        "state": EnumDef(
            "TicketState",
            {
                "OPEN": "open",
                "ASSIGNED": "assigned",
                "IN_PROGRESS": "in_progress",
                "BLOCKED": "blocked",
                "RESOLVED": "resolved",
                "CLOSED": "closed",
            },
        ),
        "assignment": EnumDef(
            "AssignmentMethod",
            {
                "MANUAL": "manual",
                "ROUND_ROBIN": "round_robin",
                "SKILL_BASED": "skill_based",
                "LOAD_BALANCED": "load_balanced",
                "AUTO_AI": "auto_ai",
            },
        ),
        "resolution_type": EnumDef(
            "ResolutionType",
            {
                "FIXED": "fixed",
                "WORKAROUND": "workaround",
                "DUPLICATE": "duplicate",
                "WONT_FIX": "wont_fix",
                "FALSE_POSITIVE": "false_positive",
            },
        ),
    },
    record_fields=[
        FieldDef("resolution", str, ""),
        FieldDef("assignee", str, ""),
        FieldDef("priority", str, "medium"),
        FieldDef("duration_sec", float, 0.0),
    ],
    key_field="ticket_id",
)

# Backward-compatible re-exports
TicketState = TicketLifecycleEngine.TicketState
AssignmentMethod = TicketLifecycleEngine.AssignmentMethod
ResolutionType = TicketLifecycleEngine.ResolutionType
TicketRecord = TicketLifecycleEngine.Record
TicketAnalysis = TicketLifecycleEngine.Analysis
TicketReport = TicketLifecycleEngine.Report
