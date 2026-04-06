"""Adaptive Scaling Controller — adaptive scaling control with ML-driven capacity management."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AdaptiveScalingController = engine(
    "AdaptiveScalingController",
    description="Adaptive Scaling Controller — adaptive scaling control with ML-driven capac...",
    enums={
        "scaling_action": EnumDef(
            "ScalingAction",
            {
                "SCALE_UP": "scale_up",
                "SCALE_DOWN": "scale_down",
                "SCALE_OUT": "scale_out",
                "SCALE_IN": "scale_in",
                "REBALANCE": "rebalance",
            },
        ),
        "scaling_source": EnumDef(
            "ScalingSource",
            {
                "ML_PREDICTION": "ml_prediction",
                "THRESHOLD": "threshold",
                "SCHEDULE": "schedule",
                "EVENT_DRIVEN": "event_driven",
                "MANUAL": "manual",
            },
        ),
        "scaling_outcome": EnumDef(
            "ScalingOutcome",
            {
                "SUCCESS": "success",
                "PARTIAL": "partial",
                "FAILED": "failed",
                "ROLLED_BACK": "rolled_back",
                "PENDING": "pending",
            },
        ),
    },
)

# Backward-compatible re-exports
ScalingAction = AdaptiveScalingController.ScalingAction
ScalingSource = AdaptiveScalingController.ScalingSource
ScalingOutcome = AdaptiveScalingController.ScalingOutcome
ScalingRecord = AdaptiveScalingController.Record
ScalingAnalysis = AdaptiveScalingController.Analysis
AdaptiveScalingReport = AdaptiveScalingController.Report
