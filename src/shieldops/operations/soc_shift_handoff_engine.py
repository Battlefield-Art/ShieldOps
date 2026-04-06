"""SOC Shift Handoff Engine — manage shift transitions and handoff completeness."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SOCShiftHandoffEngine = engine(
    "SOCShiftHandoffEngine",
    description="Manage SOC shift transitions, handoff completeness, and information continu...",
    enums={
        "handoff_type": EnumDef(
            "HandoffType",
            {
                "SHIFT_CHANGE": "shift_change",
                "ESCALATION": "escalation",
                "TEAM_TRANSFER": "team_transfer",
                "ON_CALL_ROTATION": "on_call_rotation",
                "EMERGENCY": "emergency",
            },
        ),
        "handoff_status": EnumDef(
            "HandoffStatus",
            {
                "PENDING": "pending",
                "IN_PROGRESS": "in_progress",
                "COMPLETED": "completed",
                "MISSED": "missed",
                "DELAYED": "delayed",
            },
        ),
        "handoff_priority": EnumDef(
            "HandoffPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "ROUTINE": "routine",
            },
        ),
    },
    score_field="completeness_score",
    key_field="handoff_name",
)

# Backward-compatible re-exports
HandoffType = SOCShiftHandoffEngine.HandoffType
HandoffStatus = SOCShiftHandoffEngine.HandoffStatus
HandoffPriority = SOCShiftHandoffEngine.HandoffPriority
HandoffRecord = SOCShiftHandoffEngine.Record
HandoffAnalysis = SOCShiftHandoffEngine.Analysis
HandoffReport = SOCShiftHandoffEngine.Report
