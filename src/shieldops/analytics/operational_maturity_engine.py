"""OperationalMaturityEngine — Assess and track operational maturity across SRE practice."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OperationalMaturityEngine = engine(
    "OperationalMaturityEngine",
    description="Assess and track operational maturity across the SRE practice.",
    enums={
        "maturity_domain": EnumDef(
            "MaturityDomain",
            {
                "INCIDENT_MANAGEMENT": "incident_management",
                "MONITORING": "monitoring",
                "AUTOMATION": "automation",
                "LEARNING": "learning",
                "SECURITY": "security",
            },
        ),
        "maturity_level": EnumDef(
            "MaturityLevel",
            {
                "AD_HOC": "ad_hoc",
                "REPEATABLE": "repeatable",
                "DEFINED": "defined",
                "MANAGED": "managed",
                "OPTIMIZED": "optimized",
            },
        ),
        "assessment_confidence": EnumDef(
            "AssessmentConfidence",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("practice_count", int, 0),
        FieldDef("automated_pct", float, 0.0),
    ],
)

# Backward-compatible re-exports
MaturityDomain = OperationalMaturityEngine.MaturityDomain
MaturityLevel = OperationalMaturityEngine.MaturityLevel
AssessmentConfidence = OperationalMaturityEngine.AssessmentConfidence
OperationalMaturityRecord = OperationalMaturityEngine.Record
OperationalMaturityAnalysis = OperationalMaturityEngine.Analysis
OperationalMaturityReport = OperationalMaturityEngine.Report
