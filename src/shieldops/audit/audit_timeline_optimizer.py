"""Audit Timeline Optimizer compute optimal timeline, detect preparation bottlenecks, rank aud..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AuditTimelineOptimizer = engine(
    "AuditTimelineOptimizer",
    description="Compute optimal timeline, detect preparation bottlenecks, rank audit tasks...",
    enums={
        "task_phase": EnumDef(
            "TaskPhase",
            {
                "PLANNING": "planning",
                "EVIDENCE_COLLECTION": "evidence_collection",
                "TESTING": "testing",
                "REPORTING": "reporting",
            },
        ),
        "timeline_status": EnumDef(
            "TimelineStatus",
            {
                "ON_TRACK": "on_track",
                "AT_RISK": "at_risk",
                "DELAYED": "delayed",
                "COMPLETED": "completed",
            },
        ),
        "task_priority": EnumDef(
            "TaskPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("duration_days", float, 0.0),
        FieldDef("planned_days", float, 0.0),
        FieldDef("slack_days", float, 0.0),
        FieldDef("audit_id", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="task_id",
)

# Backward-compatible re-exports
TaskPhase = AuditTimelineOptimizer.TaskPhase
TimelineStatus = AuditTimelineOptimizer.TimelineStatus
TaskPriority = AuditTimelineOptimizer.TaskPriority
AuditTimelineRecord = AuditTimelineOptimizer.Record
AuditTimelineAnalysis = AuditTimelineOptimizer.Analysis
AuditTimelineReport = AuditTimelineOptimizer.Report
