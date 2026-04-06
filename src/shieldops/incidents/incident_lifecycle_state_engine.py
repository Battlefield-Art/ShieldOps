"""Incident Lifecycle State Engine — track incident phases, compute dwell times, detect bottle..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IncidentLifecycleStateEngine = engine(
    "IncidentLifecycleStateEngine",
    description="Track incident lifecycle phases, compute dwell times, detect bottlenecks, r...",
    enums={
        "phase": EnumDef(
            "IncidentPhase",
            {
                "DETECTED": "detected",
                "TRIAGED": "triaged",
                "MITIGATED": "mitigated",
                "RESOLVED": "resolved",
                "CLOSED": "closed",
            },
        ),
        "severity": EnumDef(
            "Severity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "tracking_mode": EnumDef(
            "TrackingMode",
            {
                "REALTIME": "realtime",
                "BATCH": "batch",
                "SNAPSHOT": "snapshot",
            },
        ),
    },
    record_fields=[
        FieldDef("dwell_time_seconds", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="incident_id",
)

# Backward-compatible re-exports
IncidentPhase = IncidentLifecycleStateEngine.IncidentPhase
Severity = IncidentLifecycleStateEngine.Severity
TrackingMode = IncidentLifecycleStateEngine.TrackingMode
LifecycleStateRecord = IncidentLifecycleStateEngine.Record
LifecycleStateAnalysis = IncidentLifecycleStateEngine.Analysis
LifecycleStateReport = IncidentLifecycleStateEngine.Report
