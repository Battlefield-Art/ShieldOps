"""API Consumer Impact Analyzer. Map consumer dependencies, simulate change impact, and priori..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ApiConsumerImpactAnalyzer = engine(
    "ApiConsumerImpactAnalyzer",
    module="operations",  # uses record_item
    description="Map consumer dependencies, simulate change impact, prioritize notifications.",
    enums={
        "impact_level": EnumDef(
            "ImpactLevel",
            {
                "BREAKING": "breaking",
                "DEGRADING": "degrading",
                "COSMETIC": "cosmetic",
                "NONE": "none",
            },
        ),
        "consumer_tier": EnumDef(
            "ConsumerTier",
            {
                "PREMIUM": "premium",
                "STANDARD": "standard",
                "FREE": "free",
                "INTERNAL": "internal",
            },
        ),
        "change_type": EnumDef(
            "ChangeType",
            {
                "BREAKING": "breaking",
                "DEPRECATION": "deprecation",
                "ENHANCEMENT": "enhancement",
                "PATCH": "patch",
            },
        ),
    },
    record_fields=[
        FieldDef("consumer_id", str, ""),
        FieldDef("affected_endpoints", int, 0),
        FieldDef("request_volume", float, 0.0),
        FieldDef("notified", bool, False),
    ],
    key_field="api_name",
)

# Backward-compatible re-exports
ImpactLevel = ApiConsumerImpactAnalyzer.ImpactLevel
ConsumerTier = ApiConsumerImpactAnalyzer.ConsumerTier
ChangeType = ApiConsumerImpactAnalyzer.ChangeType
ConsumerImpactRecord = ApiConsumerImpactAnalyzer.Record
ConsumerImpactAnalysis = ApiConsumerImpactAnalyzer.Analysis
ConsumerImpactReport = ApiConsumerImpactAnalyzer.Report
