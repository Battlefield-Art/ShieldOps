"""PlatformMaturityIntelligence — platform maturity intelligence."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

PlatformMaturityIntelligence = engine(
    "PlatformMaturityIntelligence",
    module="operations",  # uses record_item
    description="Platform Maturity Intelligence.",
    enums={
        "maturity_domain": EnumDef(
            "MaturityDomain",
            {
                "OBSERVABILITY": "observability",
                "SECURITY": "security",
                "AUTOMATION": "automation",
                "RELIABILITY": "reliability",
                "GOVERNANCE": "governance",
            },
        ),
        "maturity_level": EnumDef(
            "MaturityLevel",
            {
                "INITIAL": "initial",
                "DEVELOPING": "developing",
                "DEFINED": "defined",
                "MANAGED": "managed",
                "OPTIMIZED": "optimized",
            },
        ),
        "maturity_gap": EnumDef(
            "MaturityGap",
            {
                "CRITICAL": "critical",
                "SIGNIFICANT": "significant",
                "MODERATE": "moderate",
                "MINOR": "minor",
                "NONE": "none",
            },
        ),
    },
)

# Backward-compatible re-exports
MaturityDomain = PlatformMaturityIntelligence.MaturityDomain
MaturityLevel = PlatformMaturityIntelligence.MaturityLevel
MaturityGap = PlatformMaturityIntelligence.MaturityGap
PlatformMaturityIntelligenceRecord = PlatformMaturityIntelligence.Record
PlatformMaturityIntelligenceAnalysis = PlatformMaturityIntelligence.Analysis
PlatformMaturityIntelligenceReport = PlatformMaturityIntelligence.Report
