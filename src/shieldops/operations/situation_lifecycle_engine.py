"""Situation Lifecycle Engine — track situation phases."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SituationLifecycleEngine = engine(
    "SituationLifecycleEngine",
    description="Track situation lifecycle and SLA compliance.",
    enums={
        "phase": EnumDef(
            "SituationPhase",
            {
                "NEW": "new",
                "TRIAGING": "triaging",
                "INVESTIGATING": "investigating",
                "RESPONDING": "responding",
                "RESOLVED": "resolved",
            },
        ),
        "resolution": EnumDef(
            "ResolutionMethod",
            {
                "AUTO_RESOLVED": "auto_resolved",
                "ANALYST_RESOLVED": "analyst_resolved",
                "ESCALATED": "escalated",
                "SUPPRESSED": "suppressed",
            },
        ),
        "sla": EnumDef(
            "SLATarget",
            {
                "P0_15MIN": "p0_15min",
                "P1_1HR": "p1_1hr",
                "P2_4HR": "p2_4hr",
                "P3_24HR": "p3_24hr",
            },
        ),
    },
    record_fields=[
        FieldDef("title", str, ""),
        FieldDef("analyst_id", str, ""),
        FieldDef("alert_count", int, 0),
        FieldDef("ttrs_seconds", float, 0.0),
        FieldDef("sla_breached", bool, False),
        FieldDef("resolved_at", float, 0.0),
    ],
    key_field="situation_id",
)

# Backward-compatible re-exports
SituationPhase = SituationLifecycleEngine.SituationPhase
ResolutionMethod = SituationLifecycleEngine.ResolutionMethod
SLATarget = SituationLifecycleEngine.SLATarget
SituationRecord = SituationLifecycleEngine.Record
SituationAnalysis = SituationLifecycleEngine.Analysis
SituationReport = SituationLifecycleEngine.Report
