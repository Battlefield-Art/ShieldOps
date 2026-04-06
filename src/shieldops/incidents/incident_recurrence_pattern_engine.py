"""Incident Recurrence Pattern Engine — compute recurrence frequency, detect systemic patterns..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IncidentRecurrencePatternEngine = engine(
    "IncidentRecurrencePatternEngine",
    description="Compute recurrence frequency, detect systemic patterns, rank recurrence clu...",
    enums={
        "recurrence_type": EnumDef(
            "RecurrenceType",
            {
                "EXACT": "exact",
                "SIMILAR": "similar",
                "RELATED": "related",
                "SEASONAL": "seasonal",
            },
        ),
        "pattern_scope": EnumDef(
            "PatternScope",
            {
                "SERVICE": "service",
                "TEAM": "team",
                "INFRASTRUCTURE": "infrastructure",
                "ORGANIZATION": "organization",
            },
        ),
        "recurrence_risk": EnumDef(
            "RecurrenceRisk",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("occurrence_count", int, 1),
        FieldDef("pattern_signature", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="incident_id",
)

# Backward-compatible re-exports
RecurrenceType = IncidentRecurrencePatternEngine.RecurrenceType
PatternScope = IncidentRecurrencePatternEngine.PatternScope
RecurrenceRisk = IncidentRecurrencePatternEngine.RecurrenceRisk
RecurrencePatternRecord = IncidentRecurrencePatternEngine.Record
RecurrencePatternAnalysis = IncidentRecurrencePatternEngine.Analysis
RecurrencePatternReport = IncidentRecurrencePatternEngine.Report
