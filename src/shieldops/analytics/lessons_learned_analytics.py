"""Lessons Learned Analytics — track lessons and recurrence."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

LessonsLearnedAnalyticsEngine = engine(
    "LessonsLearnedAnalyticsEngine",
    description="Track lessons learned and recurrence.",
    enums={
        "category": EnumDef(
            "LessonCategory",
            {
                "PROCESS": "process",
                "TOOLING": "tooling",
                "COMMUNICATION": "communication",
                "DETECTION": "detection",
                "RESPONSE": "response",
            },
        ),
        "recurrence": EnumDef(
            "RecurrenceRate",
            {
                "NONE": "none",
                "RARE": "rare",
                "OCCASIONAL": "occasional",
                "FREQUENT": "frequent",
                "CHRONIC": "chronic",
            },
        ),
        "status": EnumDef(
            "ImplementationStatus",
            {
                "PROPOSED": "proposed",
                "APPROVED": "approved",
                "IN_PROGRESS": "in_progress",
                "COMPLETED": "completed",
                "DEFERRED": "deferred",
            },
        ),
    },
    record_fields=[
        FieldDef("lesson_text", str, ""),
        FieldDef("action_item", str, ""),
        FieldDef("owner", str, ""),
    ],
    key_field="incident_id",
)

# Backward-compatible re-exports
LessonCategory = LessonsLearnedAnalyticsEngine.LessonCategory
RecurrenceRate = LessonsLearnedAnalyticsEngine.RecurrenceRate
ImplementationStatus = LessonsLearnedAnalyticsEngine.ImplementationStatus
LessonRecord = LessonsLearnedAnalyticsEngine.Record
LessonAnalysis = LessonsLearnedAnalyticsEngine.Analysis
LessonReport = LessonsLearnedAnalyticsEngine.Report
