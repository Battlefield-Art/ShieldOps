"""Sre Copilot Engine — SRE copilot engine with AI-assisted operational guidance."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SreCopilotEngine = engine(
    "SreCopilotEngine",
    description="Sre Copilot Engine — SRE copilot engine with AI-assisted operational guidance.",
    enums={
        "guidance_type": EnumDef(
            "GuidanceType",
            {
                "INCIDENT_RESPONSE": "incident_response",
                "CAPACITY_PLANNING": "capacity_planning",
                "OPTIMIZATION": "optimization",
                "TROUBLESHOOTING": "troubleshooting",
                "AUTOMATION": "automation",
            },
        ),
        "copilot_source": EnumDef(
            "CopilotSource",
            {
                "CONTEXT_ANALYSIS": "context_analysis",
                "HISTORICAL_DATA": "historical_data",
                "BEST_PRACTICE": "best_practice",
                "ML_RECOMMENDATION": "ml_recommendation",
                "EXPERT_SYSTEM": "expert_system",
            },
        ),
        "guidance_confidence": EnumDef(
            "GuidanceConfidence",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "SPECULATIVE": "speculative",
                "REQUIRES_VALIDATION": "requires_validation",
            },
        ),
    },
)

# Backward-compatible re-exports
GuidanceType = SreCopilotEngine.GuidanceType
CopilotSource = SreCopilotEngine.CopilotSource
GuidanceConfidence = SreCopilotEngine.GuidanceConfidence
GuidanceRecord = SreCopilotEngine.Record
GuidanceAnalysis = SreCopilotEngine.Analysis
SreCopilotReport = SreCopilotEngine.Report
