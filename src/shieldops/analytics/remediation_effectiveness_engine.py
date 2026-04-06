"""Remediation Effectiveness Engine — measure ROI."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RemediationEffectivenessEngine = engine(
    "RemediationEffectivenessEngine",
    description="Measure remediation effectiveness and ROI.",
    enums={
        "metric": EnumDef(
            "EffectivenessMetric",
            {
                "MTTR": "mttr",
                "RECURRENCE_RATE": "recurrence_rate",
                "FIRST_FIX_RATE": "first_fix_rate",
                "AUTOMATION_RATE": "automation_rate",
                "COVERAGE": "coverage",
            },
        ),
        "trend": EnumDef(
            "TrendDirection",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DECLINING": "declining",
                "VOLATILE": "volatile",
                "INSUFFICIENT_DATA": "insufficient_data",
            },
        ),
        "roi": EnumDef(
            "ROICategory",
            {
                "HIGH_ROI": "high_roi",
                "MODERATE_ROI": "moderate_roi",
                "LOW_ROI": "low_roi",
                "NEGATIVE_ROI": "negative_roi",
                "UNKNOWN": "unknown",
            },
        ),
    },
    record_fields=[
        FieldDef("value", float, 0.0),
        FieldDef("cost_dollars", float, 0.0),
        FieldDef("time_saved_hours", float, 0.0),
    ],
    key_field="remediation_id",
)

# Backward-compatible re-exports
EffectivenessMetric = RemediationEffectivenessEngine.EffectivenessMetric
TrendDirection = RemediationEffectivenessEngine.TrendDirection
ROICategory = RemediationEffectivenessEngine.ROICategory
EffectivenessRecord = RemediationEffectivenessEngine.Record
EffectivenessAnalysis = RemediationEffectivenessEngine.Analysis
EffectivenessReport = RemediationEffectivenessEngine.Report
