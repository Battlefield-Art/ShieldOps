"""Compliance Posture Drift Engine compute posture drift score, detect drift acceleration, ran..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CompliancePostureDriftEngine = engine(
    "CompliancePostureDriftEngine",
    description="Compute posture drift score, detect drift acceleration, rank domains by dri...",
    enums={
        "drift_direction": EnumDef(
            "DriftDirection",
            {
                "DEGRADING": "degrading",
                "STABLE": "stable",
                "IMPROVING": "improving",
                "UNKNOWN": "unknown",
            },
        ),
        "drift_severity": EnumDef(
            "DriftSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "posture_domain": EnumDef(
            "PostureDomain",
            {
                "ACCESS_CONTROL": "access_control",
                "DATA_PROTECTION": "data_protection",
                "NETWORK_SECURITY": "network_security",
                "LOGGING": "logging",
            },
        ),
    },
    record_fields=[
        FieldDef("baseline_score", float, 100.0),
        FieldDef("current_score", float, 100.0),
        FieldDef("description", str, ""),
    ],
    score_field="drift_score",
    key_field="domain_id",
)

# Backward-compatible re-exports
DriftDirection = CompliancePostureDriftEngine.DriftDirection
DriftSeverity = CompliancePostureDriftEngine.DriftSeverity
PostureDomain = CompliancePostureDriftEngine.PostureDomain
PostureDriftRecord = CompliancePostureDriftEngine.Record
PostureDriftAnalysis = CompliancePostureDriftEngine.Analysis
PostureDriftReport = CompliancePostureDriftEngine.Report
