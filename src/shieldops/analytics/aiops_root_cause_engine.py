"""AIOps Root Cause Engine ML-driven root cause analysis correlating signals across infrastruc..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AIOpsRootCauseEngine = engine(
    "AIOpsRootCauseEngine",
    description="AIOps Root Cause Engine ML-driven root cause analysis correlating signals a...",
    enums={
        "root_cause_type": EnumDef(
            "RootCauseType",
            {
                "INFRASTRUCTURE": "infrastructure",
                "APPLICATION": "application",
                "NETWORK": "network",
                "DATABASE": "database",
                "EXTERNAL": "external",
                "CONFIGURATION": "configuration",
                "CAPACITY": "capacity",
            },
        ),
        "correlation_method": EnumDef(
            "CorrelationMethod",
            {
                "TEMPORAL": "temporal",
                "TOPOLOGICAL": "topological",
                "STATISTICAL": "statistical",
                "CAUSAL": "causal",
                "ML_BASED": "ml_based",
            },
        ),
        "confidence_level": EnumDef(
            "ConfidenceLevel",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNCERTAIN": "uncertain",
            },
        ),
    },
    record_fields=[
        FieldDef("signal_type", str, ""),
        FieldDef("contributing_signals", int, 0),
        FieldDef("resolution_time_minutes", float, 0.0),
    ],
    score_field="confidence_score",
    key_field="incident_id",
)

# Backward-compatible re-exports
RootCauseType = AIOpsRootCauseEngine.RootCauseType
CorrelationMethod = AIOpsRootCauseEngine.CorrelationMethod
ConfidenceLevel = AIOpsRootCauseEngine.ConfidenceLevel
RootCauseRecord = AIOpsRootCauseEngine.Record
RootCauseAnalysis = AIOpsRootCauseEngine.Analysis
RootCauseReport = AIOpsRootCauseEngine.Report
