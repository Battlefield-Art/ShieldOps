"""Alert Correlation Cascade Engine build cascade tree, identify root cause alerts, quantify c..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AlertCorrelationCascadeEngine = engine(
    "AlertCorrelationCascadeEngine",
    description="Build cascade tree, identify root cause alerts, quantify cascade blast radius.",
    enums={
        "cascade_role": EnumDef(
            "CascadeRole",
            {
                "ROOT_CAUSE": "root_cause",
                "PROPAGATOR": "propagator",
                "SYMPTOM": "symptom",
                "INDEPENDENT": "independent",
            },
        ),
        "correlation_method": EnumDef(
            "CorrelationMethod",
            {
                "TEMPORAL": "temporal",
                "TOPOLOGICAL": "topological",
                "CAUSAL": "causal",
                "STATISTICAL": "statistical",
            },
        ),
        "cascade_depth": EnumDef(
            "CascadeDepth",
            {
                "SHALLOW": "shallow",
                "MODERATE": "moderate",
                "DEEP": "deep",
                "EXTREME": "extreme",
            },
        ),
    },
    record_fields=[
        FieldDef("parent_alert_id", str, ""),
        FieldDef("cascade_id", str, ""),
        FieldDef("source", str, ""),
    ],
    score_field="impact_score",
    key_field="alert_id",
)

# Backward-compatible re-exports
CascadeRole = AlertCorrelationCascadeEngine.CascadeRole
CorrelationMethod = AlertCorrelationCascadeEngine.CorrelationMethod
CascadeDepth = AlertCorrelationCascadeEngine.CascadeDepth
AlertCorrelationRecord = AlertCorrelationCascadeEngine.Record
AlertCorrelationAnalysis = AlertCorrelationCascadeEngine.Analysis
AlertCorrelationReport = AlertCorrelationCascadeEngine.Report
