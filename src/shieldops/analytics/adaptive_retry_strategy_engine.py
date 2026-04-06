"""Adaptive Retry Strategy Engine — evaluate retry policies, detect persistent failures, and o..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AdaptiveRetryStrategyEngine = engine(
    "AdaptiveRetryStrategyEngine",
    description="Optimize retry strategies with learning, detect persistent failures, and tu...",
    enums={
        "retry_policy": EnumDef(
            "RetryPolicy",
            {
                "FIXED": "fixed",
                "EXPONENTIAL": "exponential",
                "JITTERED": "jittered",
                "ADAPTIVE": "adaptive",
            },
        ),
        "failure_category": EnumDef(
            "FailureCategory",
            {
                "TRANSIENT": "transient",
                "PERSISTENT": "persistent",
                "INTERMITTENT": "intermittent",
                "CASCADING": "cascading",
            },
        ),
        "outcome": EnumDef(
            "RetryOutcome",
            {
                "SUCCEEDED": "succeeded",
                "EXHAUSTED": "exhausted",
                "CIRCUIT_BROKEN": "circuit_broken",
                "ESCALATED": "escalated",
            },
        ),
    },
    record_fields=[
        FieldDef("retry_count", int, 0),
        FieldDef("total_delay_ms", float, 0.0),
        FieldDef("success_rate", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="service_id",
)

# Backward-compatible re-exports
RetryPolicy = AdaptiveRetryStrategyEngine.RetryPolicy
FailureCategory = AdaptiveRetryStrategyEngine.FailureCategory
RetryOutcome = AdaptiveRetryStrategyEngine.RetryOutcome
AdaptiveRetryRecord = AdaptiveRetryStrategyEngine.Record
AdaptiveRetryAnalysis = AdaptiveRetryStrategyEngine.Analysis
AdaptiveRetryReport = AdaptiveRetryStrategyEngine.Report
