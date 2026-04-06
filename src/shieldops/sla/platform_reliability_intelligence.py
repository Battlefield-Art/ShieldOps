"""PlatformReliabilityIntelligence — platform reliability intelligence."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PlatformReliabilityIntelligence = engine(
    "PlatformReliabilityIntelligence",
    module="operations",  # uses record_item
    description="Platform Reliability Intelligence.",
    enums={
        "reliability_dimension": EnumDef(
            "ReliabilityDimension",
            {
                "AVAILABILITY": "availability",
                "LATENCY": "latency",
                "DURABILITY": "durability",
                "CONSISTENCY": "consistency",
                "SCALABILITY": "scalability",
            },
        ),
        "reliability_score": EnumDef(
            "ReliabilityScore",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "ACCEPTABLE": "acceptable",
                "POOR": "poor",
                "CRITICAL": "critical",
            },
        ),
        "reliability_target": EnumDef(
            "ReliabilityTarget",
            {
                "FIVE_NINES": "five_nines",
                "FOUR_NINES": "four_nines",
                "THREE_NINES": "three_nines",
                "TWO_NINES": "two_nines",
                "CUSTOM": "custom",
            },
        ),
    },
)

# Backward-compatible re-exports
ReliabilityDimension = PlatformReliabilityIntelligence.ReliabilityDimension
ReliabilityScore = PlatformReliabilityIntelligence.ReliabilityScore
ReliabilityTarget = PlatformReliabilityIntelligence.ReliabilityTarget
PlatformReliabilityIntelligenceRecord = PlatformReliabilityIntelligence.Record
PlatformReliabilityIntelligenceAnalysis = PlatformReliabilityIntelligence.Analysis
PlatformReliabilityIntelligenceReport = PlatformReliabilityIntelligence.Report
