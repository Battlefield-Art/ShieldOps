"""Entity Timeline Builder — build entity timelines and correlate events."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

EntityTimelineBuilder = engine(
    "EntityTimelineBuilder",
    description="Build entity timelines, correlate events, and detect temporal anomalies.",
    enums={
        "event_category": EnumDef(
            "EventCategory",
            {
                "AUTHENTICATION": "authentication",
                "AUTHORIZATION": "authorization",
                "DATA_ACCESS": "data_access",
                "NETWORK": "network",
                "SYSTEM": "system",
            },
        ),
        "timeline_scope": EnumDef(
            "TimelineScope",
            {
                "HOUR": "hour",
                "DAY": "day",
                "WEEK": "week",
                "MONTH": "month",
                "QUARTER": "quarter",
            },
        ),
        "correlation_level": EnumDef(
            "CorrelationLevel",
            {
                "STRONG": "strong",
                "MODERATE": "moderate",
                "WEAK": "weak",
                "NONE": "none",
                "UNKNOWN": "unknown",
            },
        ),
    },
    score_field="timeline_score",
    key_field="entity_name",
)

# Backward-compatible re-exports
EventCategory = EntityTimelineBuilder.EventCategory
TimelineScope = EntityTimelineBuilder.TimelineScope
CorrelationLevel = EntityTimelineBuilder.CorrelationLevel
TimelineRecord = EntityTimelineBuilder.Record
TimelineAnalysis = EntityTimelineBuilder.Analysis
EntityTimelineReport = EntityTimelineBuilder.Report
