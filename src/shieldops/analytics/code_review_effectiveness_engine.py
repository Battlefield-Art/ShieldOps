"""Code Review Effectiveness Engine — compute review quality score, detect bottlenecks, rank r..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CodeReviewEffectivenessEngine = engine(
    "CodeReviewEffectivenessEngine",
    description="Compute review quality score, detect bottlenecks, rank reviewers by effecti...",
    enums={
        "outcome": EnumDef(
            "ReviewOutcome",
            {
                "APPROVED": "approved",
                "CHANGES_REQUESTED": "changes_requested",
                "REJECTED": "rejected",
                "ABANDONED": "abandoned",
            },
        ),
        "depth": EnumDef(
            "ReviewDepth",
            {
                "THOROUGH": "thorough",
                "ADEQUATE": "adequate",
                "SUPERFICIAL": "superficial",
                "RUBBER_STAMP": "rubber_stamp",
            },
        ),
        "bottleneck": EnumDef(
            "BottleneckType",
            {
                "QUEUE_TIME": "queue_time",
                "REVIEWER_AVAILABILITY": "reviewer_availability",
                "SCOPE_CREEP": "scope_creep",
                "REWORK": "rework",
            },
        ),
    },
    record_fields=[
        FieldDef("reviewer_id", str, ""),
        FieldDef("review_time_hours", float, 0.0),
        FieldDef("comments_count", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="quality_score",
    key_field="review_id",
)

# Backward-compatible re-exports
ReviewOutcome = CodeReviewEffectivenessEngine.ReviewOutcome
ReviewDepth = CodeReviewEffectivenessEngine.ReviewDepth
BottleneckType = CodeReviewEffectivenessEngine.BottleneckType
CodeReviewRecord = CodeReviewEffectivenessEngine.Record
CodeReviewAnalysis = CodeReviewEffectivenessEngine.Analysis
CodeReviewReport = CodeReviewEffectivenessEngine.Report
