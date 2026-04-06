"""Learning Feedback Loop Engine — track agent learning feedback loops, evaluate feedback qual..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

LearningFeedbackLoopEngine = engine(
    "LearningFeedbackLoopEngine",
    description="Track agent learning feedback loops, evaluate feedback quality, and optimiz...",
    enums={
        "feedback_type": EnumDef(
            "FeedbackType",
            {
                "POSITIVE": "positive",
                "NEGATIVE": "negative",
                "NEUTRAL": "neutral",
                "CORRECTIVE": "corrective",
            },
        ),
        "learning_phase": EnumDef(
            "LearningPhase",
            {
                "EXPLORATION": "exploration",
                "EXPLOITATION": "exploitation",
                "EVALUATION": "evaluation",
            },
        ),
        "convergence_status": EnumDef(
            "ConvergenceStatus",
            {
                "CONVERGING": "converging",
                "DIVERGING": "diverging",
                "OSCILLATING": "oscillating",
                "CONVERGED": "converged",
            },
        ),
    },
    record_fields=[
        FieldDef("model_id", str, ""),
        FieldDef("exploration_rate", float, 0.0),
        FieldDef("accuracy_delta", float, 0.0),
        FieldDef("iteration_count", int, 0),
        FieldDef("reward_signal", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="feedback_score",
    key_field="agent_id",
)

# Backward-compatible re-exports
FeedbackType = LearningFeedbackLoopEngine.FeedbackType
LearningPhase = LearningFeedbackLoopEngine.LearningPhase
ConvergenceStatus = LearningFeedbackLoopEngine.ConvergenceStatus
LearningFeedbackRecord = LearningFeedbackLoopEngine.Record
LearningFeedbackAnalysis = LearningFeedbackLoopEngine.Analysis
LearningFeedbackReport = LearningFeedbackLoopEngine.Report
