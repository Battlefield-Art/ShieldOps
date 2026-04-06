"""Hunt Effectiveness Analytics — measure ROI and discovery rates."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

HuntEffectivenessAnalytics = engine(
    "HuntEffectivenessAnalytics",
    description="Measure hunt effectiveness, ROI, and discovery rates.",
    enums={
        "metric": EnumDef(
            "HuntMetric",
            {
                "DWELL_TIME_REDUCTION": "dwell_time_reduction",
                "THREAT_DISCOVERY_RATE": "threat_discovery_rate",
                "MEAN_TIME_TO_DETECT": "mean_time_to_detect",
                "COVERAGE_IMPROVEMENT": "coverage_improvement",
                "ANALYST_EFFICIENCY": "analyst_efficiency",
            },
        ),
        "effectiveness": EnumDef(
            "EffectivenessScore",
            {
                "EXCEPTIONAL": "exceptional",
                "ABOVE_AVERAGE": "above_average",
                "AVERAGE": "average",
                "BELOW_AVERAGE": "below_average",
                "INEFFECTIVE": "ineffective",
            },
        ),
        "roi_category": EnumDef(
            "ROICategory",
            {
                "HIGH_ROI": "high_roi",
                "POSITIVE_ROI": "positive_roi",
                "NEUTRAL": "neutral",
                "NEGATIVE_ROI": "negative_roi",
                "UNDETERMINED": "undetermined",
            },
        ),
    },
    record_fields=[
        FieldDef("value", float, 0.0),
        FieldDef("cost_hours", float, 0.0),
        FieldDef("threats_found", int, 0),
        FieldDef("manual_equivalent_hours", float, 0.0),
    ],
    key_field="hunt_id",
)

# Backward-compatible re-exports
HuntMetric = HuntEffectivenessAnalytics.HuntMetric
EffectivenessScore = HuntEffectivenessAnalytics.EffectivenessScore
ROICategory = HuntEffectivenessAnalytics.ROICategory
HuntEffectivenessRecord = HuntEffectivenessAnalytics.Record
HuntEffectivenessAnalysis = HuntEffectivenessAnalytics.Analysis
HuntEffectivenessReport = HuntEffectivenessAnalytics.Report
