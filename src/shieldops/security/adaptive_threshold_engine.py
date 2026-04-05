"""AdaptiveThresholdEngine — auto-adjust risk thresholds based on baseline drift."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AdaptiveThresholdEngine = engine(
    "AdaptiveThresholdEngine",
    description="Auto-adjust risk thresholds based on baseline drift.",
    enums={
        "drift_direction": EnumDef(
            "DriftDirection",
            {
                "INCREASING": "increasing",
                "DECREASING": "decreasing",
                "STABLE": "stable",
            },
        ),
        "adaptation_strategy": EnumDef(
            "AdaptationStrategy",
            {
                "CONSERVATIVE": "conservative",
                "MODERATE": "moderate",
                "AGGRESSIVE": "aggressive",
            },
        ),
        "threshold_status": EnumDef(
            "ThresholdStatus",
            {
                "ACTIVE": "active",
                "PROPOSED": "proposed",
                "RETIRED": "retired",
            },
        ),
    },
    record_fields=[
        FieldDef("current_threshold", float, 0.0),
        FieldDef("baseline_value", float, 0.0),
        FieldDef("entity", str, ""),
    ],
)

# Backward-compatible re-exports
DriftDirection = AdaptiveThresholdEngine.DriftDirection
AdaptationStrategy = AdaptiveThresholdEngine.AdaptationStrategy
ThresholdStatus = AdaptiveThresholdEngine.ThresholdStatus
AdaptiveThresholdRecord = AdaptiveThresholdEngine.Record
AdaptiveThresholdAnalysis = AdaptiveThresholdEngine.Analysis
AdaptiveThresholdReport = AdaptiveThresholdEngine.Report
