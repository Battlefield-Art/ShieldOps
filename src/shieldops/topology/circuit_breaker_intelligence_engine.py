"""Circuit Breaker Intelligence Engine. Analyze trip frequency, detect flapping breakers, and..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CircuitBreakerIntelligenceEngine = engine(
    "CircuitBreakerIntelligenceEngine",
    module="operations",  # uses record_item
    description="Analyze trip frequency, detect flapping breakers, and recommend threshold t...",
    enums={
        "breaker_state": EnumDef(
            "BreakerState",
            {
                "CLOSED": "closed",
                "OPEN": "open",
                "HALF_OPEN": "half_open",
                "DISABLED": "disabled",
            },
        ),
        "trip_cause": EnumDef(
            "TripCause",
            {
                "TIMEOUT": "timeout",
                "ERROR_RATE": "error_rate",
                "OVERLOAD": "overload",
                "MANUAL": "manual",
            },
        ),
        "flapping_status": EnumDef(
            "FlappingStatus",
            {
                "STABLE": "stable",
                "OCCASIONAL": "occasional",
                "FREQUENT": "frequent",
                "CRITICAL": "critical",
            },
        ),
    },
    record_fields=[
        FieldDef("trip_count", int, 0),
        FieldDef("error_threshold", float, 50.0),
        FieldDef("current_error_rate", float, 0.0),
    ],
    key_field="breaker_name",
)

# Backward-compatible re-exports
BreakerState = CircuitBreakerIntelligenceEngine.BreakerState
TripCause = CircuitBreakerIntelligenceEngine.TripCause
FlappingStatus = CircuitBreakerIntelligenceEngine.FlappingStatus
CircuitBreakerRecord = CircuitBreakerIntelligenceEngine.Record
CircuitBreakerAnalysis = CircuitBreakerIntelligenceEngine.Analysis
CircuitBreakerReport = CircuitBreakerIntelligenceEngine.Report
