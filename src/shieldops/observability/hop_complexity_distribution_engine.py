"""Hop Complexity Distribution Engine — analyze investigation complexity distribution (4:3:2:1..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

HopComplexityDistributionEngine = engine(
    "HopComplexityDistributionEngine",
    description="Analyze investigation complexity distribution (4:3:2:1 ratio), detect distr...",
    enums={
        "complexity_bucket": EnumDef(
            "ComplexityBucket",
            {
                "ONE_HOP": "one_hop",
                "TWO_HOP": "two_hop",
                "THREE_HOP": "three_hop",
                "FOUR_PLUS_HOP": "four_plus_hop",
            },
        ),
        "distribution_trend": EnumDef(
            "DistributionTrend",
            {
                "SHIFTING_COMPLEX": "shifting_complex",
                "STABLE": "stable",
                "SHIFTING_SIMPLE": "shifting_simple",
                "BIMODAL": "bimodal",
            },
        ),
        "analysis_period": EnumDef(
            "AnalysisPeriod",
            {
                "HOURLY": "hourly",
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
            },
        ),
    },
    record_fields=[
        FieldDef("hop_count", int, 1),
        FieldDef("period_label", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="investigation_id",
)

# Backward-compatible re-exports
ComplexityBucket = HopComplexityDistributionEngine.ComplexityBucket
DistributionTrend = HopComplexityDistributionEngine.DistributionTrend
AnalysisPeriod = HopComplexityDistributionEngine.AnalysisPeriod
HopComplexityDistributionRecord = HopComplexityDistributionEngine.Record
HopComplexityDistributionAnalysis = HopComplexityDistributionEngine.Analysis
HopComplexityDistributionReport = HopComplexityDistributionEngine.Report
