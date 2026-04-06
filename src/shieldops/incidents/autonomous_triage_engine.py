"""Autonomous Triage Engine — autonomous incident triage and classification."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutonomousTriageEngine = engine(
    "AutonomousTriageEngine",
    description="Autonomous Triage Engine for incident triage and classification.",
    enums={
        "triage_decision": EnumDef(
            "TriageDecision",
            {
                "INVESTIGATE": "investigate",
                "ESCALATE": "escalate",
                "AUTO_RESOLVE": "auto_resolve",
                "DEFER": "defer",
            },
        ),
        "urgency_level": EnumDef(
            "UrgencyLevel",
            {
                "IMMEDIATE": "immediate",
                "URGENT": "urgent",
                "STANDARD": "standard",
                "LOW": "low",
            },
        ),
        "triage_confidence": EnumDef(
            "TriageConfidence",
            {
                "CERTAIN": "certain",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
            },
        ),
    },
)

# Backward-compatible re-exports
TriageDecision = AutonomousTriageEngine.TriageDecision
UrgencyLevel = AutonomousTriageEngine.UrgencyLevel
TriageConfidence = AutonomousTriageEngine.TriageConfidence
TriageRecord = AutonomousTriageEngine.Record
TriageAnalysis = AutonomousTriageEngine.Analysis
AutonomousTriageReport = AutonomousTriageEngine.Report
