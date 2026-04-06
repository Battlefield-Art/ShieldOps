"""Investigation Trajectory Scorer Engine — score investigation path quality and efficiency, i..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

InvestigationTrajectoryScorerEngine = engine(
    "InvestigationTrajectoryScorerEngine",
    description="Score investigation path quality and efficiency, identify trajectory ineffi...",
    enums={
        "trajectory_quality": EnumDef(
            "TrajectoryQuality",
            {
                "OPTIMAL": "optimal",
                "GOOD": "good",
                "SUBOPTIMAL": "suboptimal",
                "WASTEFUL": "wasteful",
            },
        ),
        "scoring_dimension": EnumDef(
            "ScoringDimension",
            {
                "EFFICIENCY": "efficiency",
                "COMPLETENESS": "completeness",
                "ACCURACY": "accuracy",
                "TIMELINESS": "timeliness",
            },
        ),
        "deviation_type": EnumDef(
            "DeviationType",
            {
                "UNNECESSARY_DETOUR": "unnecessary_detour",
                "MISSED_SHORTCUT": "missed_shortcut",
                "WRONG_BRANCH": "wrong_branch",
                "PREMATURE_CONCLUSION": "premature_conclusion",
            },
        ),
    },
    record_fields=[
        FieldDef("steps_taken", int, 0),
        FieldDef("optimal_steps", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="dimension_score",
    key_field="investigation_id",
)

# Backward-compatible re-exports
TrajectoryQuality = InvestigationTrajectoryScorerEngine.TrajectoryQuality
ScoringDimension = InvestigationTrajectoryScorerEngine.ScoringDimension
DeviationType = InvestigationTrajectoryScorerEngine.DeviationType
InvestigationTrajectoryScorerRecord = InvestigationTrajectoryScorerEngine.Record
InvestigationTrajectoryScorerAnalysis = InvestigationTrajectoryScorerEngine.Analysis
InvestigationTrajectoryScorerReport = InvestigationTrajectoryScorerEngine.Report
