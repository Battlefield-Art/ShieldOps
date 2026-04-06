"""Learning Feedback Loop Engine Process feedback signals through OODA loops with adaptation r..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

LearningFeedbackLoopEngine = engine(
    "LearningFeedbackLoopEngine",
    description="Process feedback signals through OODA loops with adaptation rate and stalen...",
    enums={
        "signal": EnumDef(
            "FeedbackSignal",
            {
                "POSITIVE": "positive",
                "NEGATIVE": "negative",
                "NEUTRAL": "neutral",
                "AMBIGUOUS": "ambiguous",
            },
        ),
        "stage": EnumDef(
            "LoopStage",
            {
                "OBSERVE": "observe",
                "ORIENT": "orient",
                "DECIDE": "decide",
                "ACT": "act",
            },
        ),
        "speed": EnumDef(
            "AdaptationSpeed",
            {
                "IMMEDIATE": "immediate",
                "GRADUAL": "gradual",
                "DELAYED": "delayed",
                "NONE": "none",
            },
        ),
    },
    record_fields=[
        FieldDef("signal_strength", float, 0.0),
        FieldDef("loop_iteration", int, 0),
    ],
    key_field="agent_id",
)

# Backward-compatible re-exports
FeedbackSignal = LearningFeedbackLoopEngine.FeedbackSignal
LoopStage = LearningFeedbackLoopEngine.LoopStage
AdaptationSpeed = LearningFeedbackLoopEngine.AdaptationSpeed
FeedbackRecord = LearningFeedbackLoopEngine.Record
FeedbackAnalysis = LearningFeedbackLoopEngine.Analysis
FeedbackReport = LearningFeedbackLoopEngine.Report
