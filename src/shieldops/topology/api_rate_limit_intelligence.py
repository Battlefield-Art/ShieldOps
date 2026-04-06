"""API Rate Limit Intelligence. Predict throttling events, analyze quota utilization, and reco..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ApiRateLimitIntelligence = engine(
    "ApiRateLimitIntelligence",
    module="operations",  # uses record_item
    description="Predict throttling, analyze quota utilization, recommend quota adjustments.",
    enums={
        "quota_status": EnumDef(
            "QuotaStatus",
            {
                "HEALTHY": "healthy",
                "WARNING": "warning",
                "NEAR_LIMIT": "near_limit",
                "EXCEEDED": "exceeded",
            },
        ),
        "throttle_risk": EnumDef(
            "ThrottleRisk",
            {
                "IMMINENT": "imminent",
                "LIKELY": "likely",
                "POSSIBLE": "possible",
                "UNLIKELY": "unlikely",
            },
        ),
        "adjustment_direction": EnumDef(
            "AdjustmentDirection",
            {
                "INCREASE": "increase",
                "DECREASE": "decrease",
                "MAINTAIN": "maintain",
                "RESTRUCTURE": "restructure",
            },
        ),
    },
    record_fields=[
        FieldDef("consumer_id", str, ""),
        FieldDef("current_usage", float, 0.0),
        FieldDef("quota_limit", float, 1000.0),
        FieldDef("utilization_pct", float, 0.0),
    ],
    key_field="api_name",
)

# Backward-compatible re-exports
QuotaStatus = ApiRateLimitIntelligence.QuotaStatus
ThrottleRisk = ApiRateLimitIntelligence.ThrottleRisk
AdjustmentDirection = ApiRateLimitIntelligence.AdjustmentDirection
RateLimitRecord = ApiRateLimitIntelligence.Record
RateLimitAnalysis = ApiRateLimitIntelligence.Analysis
RateLimitReport = ApiRateLimitIntelligence.Report
