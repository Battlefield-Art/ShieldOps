"""Reliability Improvement Tracker compute improvement effectiveness, detect stalled initiativ..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ReliabilityImprovementTracker = engine(
    "ReliabilityImprovementTracker",
    description="Compute improvement effectiveness, detect stalled initiatives, rank by reli...",
    enums={
        "initiative_status": EnumDef(
            "InitiativeStatus",
            {
                "PLANNED": "planned",
                "IN_PROGRESS": "in_progress",
                "COMPLETED": "completed",
                "STALLED": "stalled",
            },
        ),
        "improvement_type": EnumDef(
            "ImprovementType",
            {
                "ARCHITECTURE": "architecture",
                "PROCESS": "process",
                "TOOLING": "tooling",
                "TRAINING": "training",
            },
        ),
        "impact_level": EnumDef(
            "ImpactLevel",
            {
                "TRANSFORMATIVE": "transformative",
                "SIGNIFICANT": "significant",
                "MODERATE": "moderate",
                "MINIMAL": "minimal",
            },
        ),
    },
    record_fields=[
        FieldDef("reliability_before", float, 0.0),
        FieldDef("reliability_after", float, 0.0),
        FieldDef("effort_hours", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="initiative_id",
)

# Backward-compatible re-exports
InitiativeStatus = ReliabilityImprovementTracker.InitiativeStatus
ImprovementType = ReliabilityImprovementTracker.ImprovementType
ImpactLevel = ReliabilityImprovementTracker.ImpactLevel
ReliabilityImprovementRecord = ReliabilityImprovementTracker.Record
ReliabilityImprovementAnalysis = ReliabilityImprovementTracker.Analysis
ReliabilityImprovementReport = ReliabilityImprovementTracker.Report
