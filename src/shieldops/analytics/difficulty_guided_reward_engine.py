"""Difficulty Guided Reward Engine — implements Dr. Zero reward function for SRE agent training."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DifficultyGuidedRewardEngine = engine(
    "DifficultyGuidedRewardEngine",
    description="Implements Dr. Zero reward function for SRE agent training.",
    enums={
        "reward_zone": EnumDef(
            "RewardZone",
            {
                "TRIVIAL": "trivial",
                "PRODUCTIVE": "productive",
                "CHALLENGING": "challenging",
                "IMPOSSIBLE": "impossible",
            },
        ),
        "format_reward": EnumDef(
            "FormatRewardLevel",
            {
                "FULL": "full",
                "PARTIAL": "partial",
                "MINIMAL": "minimal",
                "NONE": "none",
            },
        ),
        "penalty_type": EnumDef(
            "PenaltyType",
            {
                "TRIVIAL_PENALTY": "trivial_penalty",
                "IMPOSSIBLE_PENALTY": "impossible_penalty",
                "FORMAT_PENALTY": "format_penalty",
                "NO_PENALTY": "no_penalty",
            },
        ),
    },
    record_fields=[
        FieldDef("raw_reward", float, 0.0),
        FieldDef("correctness_score", float, 0.0),
        FieldDef("description", str, ""),
    ],
    score_field="difficulty_score",
    key_field="solver_id",
)

# Backward-compatible re-exports
RewardZone = DifficultyGuidedRewardEngine.RewardZone
FormatRewardLevel = DifficultyGuidedRewardEngine.FormatRewardLevel
PenaltyType = DifficultyGuidedRewardEngine.PenaltyType
DifficultyRewardRecord = DifficultyGuidedRewardEngine.Record
DifficultyRewardAnalysis = DifficultyGuidedRewardEngine.Analysis
DifficultyRewardReport = DifficultyGuidedRewardEngine.Report
