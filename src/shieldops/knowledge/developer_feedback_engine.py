"""DeveloperFeedbackEngine Developer feedback collection, sentiment analysis, satisfaction sco..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

DeveloperFeedbackEngine = engine(
    "DeveloperFeedbackEngine",
    description="Developer feedback collection with sentiment analysis.",
    enums={
        "feedback_category": EnumDef(
            "FeedbackCategory",
            {
                "TOOLING": "tooling",
                "DOCUMENTATION": "documentation",
                "INFRASTRUCTURE": "infrastructure",
                "PROCESS": "process",
                "CULTURE": "culture",
            },
        ),
        "feedback_sentiment": EnumDef(
            "FeedbackSentiment",
            {
                "POSITIVE": "positive",
                "NEUTRAL": "neutral",
                "NEGATIVE": "negative",
                "MIXED": "mixed",
                "UNKNOWN": "unknown",
            },
        ),
        "feedback_channel": EnumDef(
            "FeedbackChannel",
            {
                "SURVEY": "survey",
                "RETRO": "retro",
                "SLACK": "slack",
                "TICKET": "ticket",
                "INTERVIEW": "interview",
            },
        ),
    },
)

# Backward-compatible re-exports
FeedbackCategory = DeveloperFeedbackEngine.FeedbackCategory
FeedbackSentiment = DeveloperFeedbackEngine.FeedbackSentiment
FeedbackChannel = DeveloperFeedbackEngine.FeedbackChannel
DeveloperFeedbackRecord = DeveloperFeedbackEngine.Record
DeveloperFeedbackAnalysis = DeveloperFeedbackEngine.Analysis
DeveloperFeedbackReport = DeveloperFeedbackEngine.Report
