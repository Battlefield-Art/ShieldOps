"""Reward Signal Engineering Engine — design reward functions, evaluate signal quality, and op..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RewardSignalEngineeringEngine = engine(
    "RewardSignalEngineeringEngine",
    description="Design reward functions, evaluate signal quality, and optimize reward shapi...",
    enums={
        "reward_type": EnumDef(
            "RewardType",
            {
                "SHAPED": "shaped",
                "SPARSE": "sparse",
                "DENSE": "dense",
                "INTRINSIC": "intrinsic",
            },
        ),
        "signal_quality": EnumDef(
            "SignalQuality",
            {
                "CLEAN": "clean",
                "NOISY": "noisy",
                "DELAYED": "delayed",
                "CORRUPTED": "corrupted",
            },
        ),
        "optimization_goal": EnumDef(
            "OptimizationGoal",
            {
                "MAXIMIZE_THROUGHPUT": "maximize_throughput",
                "MINIMIZE_LATENCY": "minimize_latency",
                "BALANCE_COST": "balance_cost",
                "MAXIMIZE_RELIABILITY": "maximize_reliability",
            },
        ),
    },
    record_fields=[
        FieldDef("reward_value", float, 0.0),
        FieldDef("signal_delay_ms", float, 0.0),
        FieldDef("noise_level", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="agent_id",
)

# Backward-compatible re-exports
RewardType = RewardSignalEngineeringEngine.RewardType
SignalQuality = RewardSignalEngineeringEngine.SignalQuality
OptimizationGoal = RewardSignalEngineeringEngine.OptimizationGoal
RewardSignalRecord = RewardSignalEngineeringEngine.Record
RewardSignalAnalysis = RewardSignalEngineeringEngine.Analysis
RewardSignalReport = RewardSignalEngineeringEngine.Report
