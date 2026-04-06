"""EngineeringEffectivenessEngine — engineering effectiveness engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

EngineeringEffectivenessEngine = engine(
    "EngineeringEffectivenessEngine",
    module="operations",  # uses record_item
    description="Engineering Effectiveness Engine.",
    enums={
        "effectiveness_metric": EnumDef(
            "EffectivenessMetric",
            {
                "DORA_METRICS": "dora_metrics",
                "CYCLE_TIME": "cycle_time",
                "CODE_QUALITY": "code_quality",
                "INCIDENT_RESPONSE": "incident_response",
                "AUTOMATION_RATE": "automation_rate",
            },
        ),
        "team_performance": EnumDef(
            "TeamPerformance",
            {
                "ELITE": "elite",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "UNKNOWN": "unknown",
            },
        ),
        "improvement_area": EnumDef(
            "ImprovementArea",
            {
                "DEPLOYMENT": "deployment",
                "TESTING": "testing",
                "MONITORING": "monitoring",
                "INCIDENT_MGMT": "incident_mgmt",
                "AUTOMATION": "automation",
            },
        ),
    },
)

# Backward-compatible re-exports
EffectivenessMetric = EngineeringEffectivenessEngine.EffectivenessMetric
TeamPerformance = EngineeringEffectivenessEngine.TeamPerformance
ImprovementArea = EngineeringEffectivenessEngine.ImprovementArea
EngineeringEffectivenessEngineRecord = EngineeringEffectivenessEngine.Record
EngineeringEffectivenessEngineAnalysis = EngineeringEffectivenessEngine.Analysis
EngineeringEffectivenessEngineReport = EngineeringEffectivenessEngine.Report
