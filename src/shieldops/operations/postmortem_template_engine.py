"""Postmortem Template Engine — generate and track postmortems."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

PostmortemTemplateEngine = engine(
    "PostmortemTemplateEngine",
    module="operations",  # uses record_item
    description="Generate and track postmortem templates.",
    enums={
        "section": EnumDef(
            "TemplateSection",
            {
                "SUMMARY": "summary",
                "TIMELINE": "timeline",
                "ROOT_CAUSE": "root_cause",
                "IMPACT": "impact",
                "ACTION_ITEMS": "action_items",
            },
        ),
        "depth": EnumDef(
            "AnalysisDepth",
            {
                "SHALLOW": "shallow",
                "STANDARD": "standard",
                "DEEP": "deep",
                "EXHAUSTIVE": "exhaustive",
                "BLAMELESS": "blameless",
            },
        ),
        "priority": EnumDef(
            "ActionItemPriority",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "OPTIONAL": "optional",
            },
        ),
    },
    record_fields=[
        FieldDef("content", str, ""),
        FieldDef("owner", str, ""),
        FieldDef("completed", bool, False),
    ],
    key_field="incident_id",
)

# Backward-compatible re-exports
TemplateSection = PostmortemTemplateEngine.TemplateSection
AnalysisDepth = PostmortemTemplateEngine.AnalysisDepth
ActionItemPriority = PostmortemTemplateEngine.ActionItemPriority
PostmortemRecord = PostmortemTemplateEngine.Record
PostmortemAnalysis = PostmortemTemplateEngine.Analysis
PostmortemReport = PostmortemTemplateEngine.Report
