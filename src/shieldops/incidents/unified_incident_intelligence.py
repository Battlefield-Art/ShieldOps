"""UnifiedIncidentIntelligence — unified incident intelligence."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

UnifiedIncidentIntelligence = engine(
    "UnifiedIncidentIntelligence",
    module="operations",  # uses record_item
    description="Unified Incident Intelligence.",
    enums={
        "incident_domain": EnumDef(
            "IncidentDomain",
            {
                "SECURITY": "security",
                "AVAILABILITY": "availability",
                "PERFORMANCE": "performance",
                "COMPLIANCE": "compliance",
                "DATA": "data",
            },
        ),
        "intelligence_type": EnumDef(
            "IntelligenceType",
            {
                "ROOT_CAUSE": "root_cause",
                "IMPACT": "impact",
                "CORRELATION": "correlation",
                "PREDICTION": "prediction",
                "RECOMMENDATION": "recommendation",
            },
        ),
        "incident_phase": EnumDef(
            "IncidentPhase",
            {
                "DETECTION": "detection",
                "TRIAGE": "triage",
                "CONTAINMENT": "containment",
                "ERADICATION": "eradication",
                "RECOVERY": "recovery",
            },
        ),
    },
)

# Backward-compatible re-exports
IncidentDomain = UnifiedIncidentIntelligence.IncidentDomain
IntelligenceType = UnifiedIncidentIntelligence.IntelligenceType
IncidentPhase = UnifiedIncidentIntelligence.IncidentPhase
UnifiedIncidentIntelligenceRecord = UnifiedIncidentIntelligence.Record
UnifiedIncidentIntelligenceAnalysis = UnifiedIncidentIntelligence.Analysis
UnifiedIncidentIntelligenceReport = UnifiedIncidentIntelligence.Report
