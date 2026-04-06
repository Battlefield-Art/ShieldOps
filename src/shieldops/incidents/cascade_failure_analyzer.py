"""Cascade Failure Analyzer — compute cascade depth, detect trigger services, rank by propagat..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CascadeFailureAnalyzer = engine(
    "CascadeFailureAnalyzer",
    description="Compute cascade depth, detect cascade trigger services, rank cascades by pr...",
    enums={
        "cascade_phase": EnumDef(
            "CascadePhase",
            {
                "TRIGGER": "trigger",
                "PROPAGATION": "propagation",
                "AMPLIFICATION": "amplification",
                "STABILIZATION": "stabilization",
            },
        ),
        "failure_type": EnumDef(
            "FailureType",
            {
                "TIMEOUT": "timeout",
                "OVERLOAD": "overload",
                "DATA_CORRUPTION": "data_corruption",
                "DEPENDENCY": "dependency",
            },
        ),
        "cascade_scope": EnumDef(
            "CascadeScope",
            {
                "SERVICE": "service",
                "CLUSTER": "cluster",
                "REGION": "region",
                "GLOBAL": "global",
            },
        ),
    },
    record_fields=[
        FieldDef("cascade_depth", int, 0),
        FieldDef("propagation_time_seconds", float, 0.0),
        FieldDef("trigger_service", str, ""),
        FieldDef("affected_services", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="incident_id",
)

# Backward-compatible re-exports
CascadePhase = CascadeFailureAnalyzer.CascadePhase
FailureType = CascadeFailureAnalyzer.FailureType
CascadeScope = CascadeFailureAnalyzer.CascadeScope
CascadeFailureRecord = CascadeFailureAnalyzer.Record
CascadeFailureAnalysis = CascadeFailureAnalyzer.Analysis
CascadeFailureReport = CascadeFailureAnalyzer.Report
