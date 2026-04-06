"""Cognitive Incident Triage Engine AI-driven incident triage recommending severity, routing,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CognitiveIncidentTriageEngine = engine(
    "CognitiveIncidentTriageEngine",
    description="Cognitive Incident Triage Engine AI-driven incident triage recommending sev...",
    enums={
        "triage_decision": EnumDef(
            "TriageDecision",
            {
                "AUTO_RESOLVE": "auto_resolve",
                "ASSIGN_ONCALL": "assign_oncall",
                "ESCALATE": "escalate",
                "DEFER": "defer",
                "INVESTIGATE": "investigate",
            },
        ),
        "recommended_severity": EnumDef(
            "SeverityRecommendation",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFORMATIONAL": "informational",
            },
        ),
        "confidence": EnumDef(
            "TriageConfidence",
            {
                "DEFINITIVE": "definitive",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("similar_incident_count", int, 0),
        FieldDef("responder_load_pct", float, 0.0),
        FieldDef("resolution_time_minutes", float, 0.0),
    ],
    score_field="blast_radius_score",
    key_field="incident_id",
)

# Backward-compatible re-exports
TriageDecision = CognitiveIncidentTriageEngine.TriageDecision
SeverityRecommendation = CognitiveIncidentTriageEngine.SeverityRecommendation
TriageConfidence = CognitiveIncidentTriageEngine.TriageConfidence
TriageRecord = CognitiveIncidentTriageEngine.Record
TriageAnalysis = CognitiveIncidentTriageEngine.Analysis
TriageReport = CognitiveIncidentTriageEngine.Report
