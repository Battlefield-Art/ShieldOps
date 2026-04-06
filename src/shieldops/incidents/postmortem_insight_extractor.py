"""Postmortem Insight Extractor — extract actionable insights, detect recurring themes, rank i..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

PostmortemInsightExtractor = engine(
    "PostmortemInsightExtractor",
    description="Extract actionable insights from postmortems, detect recurring themes, rank...",
    enums={
        "insight_type": EnumDef(
            "InsightType",
            {
                "ROOT_CAUSE": "root_cause",
                "CONTRIBUTING_FACTOR": "contributing_factor",
                "ACTION_ITEM": "action_item",
                "PREVENTION": "prevention",
            },
        ),
        "theme_category": EnumDef(
            "ThemeCategory",
            {
                "INFRASTRUCTURE": "infrastructure",
                "CODE": "code",
                "PROCESS": "process",
                "HUMAN": "human",
            },
        ),
        "insight_priority": EnumDef(
            "InsightPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
    },
    record_fields=[
        FieldDef("insight_text", str, ""),
        FieldDef("description", str, ""),
    ],
    score_field="prevention_score",
    key_field="incident_id",
)

# Backward-compatible re-exports
InsightType = PostmortemInsightExtractor.InsightType
ThemeCategory = PostmortemInsightExtractor.ThemeCategory
InsightPriority = PostmortemInsightExtractor.InsightPriority
PostmortemInsightRecord = PostmortemInsightExtractor.Record
PostmortemInsightAnalysis = PostmortemInsightExtractor.Analysis
PostmortemInsightReport = PostmortemInsightExtractor.Report
