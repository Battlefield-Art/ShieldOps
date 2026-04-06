"""SOCAssistantAnalyticsEngine — Track SOC assistant query effectiveness and knowledge gaps."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SOCAssistantAnalyticsEngine = engine(
    "SOCAssistantAnalyticsEngine",
    description="Track SOC assistant query effectiveness and knowledge gaps.",
    enums={
        "query_category": EnumDef(
            "QueryCategory",
            {
                "INVESTIGATION": "investigation",
                "THREAT_HUNT": "threat_hunt",
                "COMPLIANCE": "compliance",
                "STATUS": "status",
                "EXPLANATION": "explanation",
            },
        ),
        "response_quality": EnumDef(
            "ResponseQuality",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "ADEQUATE": "adequate",
                "POOR": "poor",
            },
        ),
        "analyst_satisfaction": EnumDef(
            "AnalystSatisfaction",
            {
                "VERY_SATISFIED": "very_satisfied",
                "SATISFIED": "satisfied",
                "NEUTRAL": "neutral",
                "DISSATISFIED": "dissatisfied",
            },
        ),
    },
    record_fields=[
        FieldDef("response_time_ms", float, 0.0),
        FieldDef("analyst_id", str, ""),
    ],
)

# Backward-compatible re-exports
QueryCategory = SOCAssistantAnalyticsEngine.QueryCategory
ResponseQuality = SOCAssistantAnalyticsEngine.ResponseQuality
AnalystSatisfaction = SOCAssistantAnalyticsEngine.AnalystSatisfaction
AssistantQueryRecord = SOCAssistantAnalyticsEngine.Record
AssistantAnalysis = SOCAssistantAnalyticsEngine.Analysis
AssistantReport = SOCAssistantAnalyticsEngine.Report
