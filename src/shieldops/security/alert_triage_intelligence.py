"""Alert Triage Intelligence — intelligent alert triage with ML-assisted prioritization."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AlertTriageIntelligence = engine(
    "AlertTriageIntelligence",
    description="Alert Triage Intelligence — intelligent alert triage with ML-assisted prior...",
    enums={
        "triage_priority": EnumDef(
            "TriagePriority",
            {
                "P1_CRITICAL": "p1_critical",
                "P2_HIGH": "p2_high",
                "P3_MEDIUM": "p3_medium",
                "P4_LOW": "p4_low",
                "P5_INFORMATIONAL": "p5_informational",
            },
        ),
        "triage_source": EnumDef(
            "TriageSource",
            {
                "ML_MODEL": "ml_model",
                "RULE_ENGINE": "rule_engine",
                "ANALYST_FEEDBACK": "analyst_feedback",
                "HISTORICAL": "historical",
                "CONTEXT": "context",
            },
        ),
        "triage_decision": EnumDef(
            "TriageDecision",
            {
                "INVESTIGATE": "investigate",
                "ESCALATE": "escalate",
                "SUPPRESS": "suppress",
                "AUTO_CLOSE": "auto_close",
                "ENRICH": "enrich",
            },
        ),
    },
)

# Backward-compatible re-exports
TriagePriority = AlertTriageIntelligence.TriagePriority
TriageSource = AlertTriageIntelligence.TriageSource
TriageDecision = AlertTriageIntelligence.TriageDecision
TriageRecord = AlertTriageIntelligence.Record
TriageAnalysis = AlertTriageIntelligence.Analysis
AlertTriageReport = AlertTriageIntelligence.Report
