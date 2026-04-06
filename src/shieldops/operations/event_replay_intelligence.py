"""Event Replay Intelligence — compute replay impact, detect idempotency violations, rank repl..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EventReplayIntelligence = engine(
    "EventReplayIntelligence",
    module="operations",  # uses record_item
    description="Compute replay impact, detect idempotency violations, rank replay candidate...",
    enums={
        "replay_scope": EnumDef(
            "ReplayScope",
            {
                "FULL": "full",
                "PARTIAL": "partial",
                "SELECTIVE": "selective",
                "POINT_IN_TIME": "point_in_time",
            },
        ),
        "safety_level": EnumDef(
            "SafetyLevel",
            {
                "SAFE": "safe",
                "CAUTION": "caution",
                "RISKY": "risky",
                "BLOCKED": "blocked",
            },
        ),
        "idempotency_status": EnumDef(
            "IdempotencyStatus",
            {
                "GUARANTEED": "guaranteed",
                "LIKELY": "likely",
                "UNCERTAIN": "uncertain",
                "VIOLATED": "violated",
            },
        ),
    },
    record_fields=[
        FieldDef("event_count", int, 0),
        FieldDef("target_service", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="impact_score",
    key_field="replay_id",
)

# Backward-compatible re-exports
ReplayScope = EventReplayIntelligence.ReplayScope
SafetyLevel = EventReplayIntelligence.SafetyLevel
IdempotencyStatus = EventReplayIntelligence.IdempotencyStatus
EventReplayRecord = EventReplayIntelligence.Record
EventReplayAnalysis = EventReplayIntelligence.Analysis
EventReplayReport = EventReplayIntelligence.Report
