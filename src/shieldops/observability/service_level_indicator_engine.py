"""ServiceLevelIndicatorEngine — Track and validate SLI definitions against actual metrics."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ServiceLevelIndicatorEngine = engine(
    "ServiceLevelIndicatorEngine",
    description="Track and validate SLI definitions against actual metrics.",
    enums={
        "sli_type": EnumDef(
            "SLIType",
            {
                "AVAILABILITY": "availability",
                "LATENCY": "latency",
                "THROUGHPUT": "throughput",
                "ERROR_RATE": "error_rate",
            },
        ),
        "sli_status": EnumDef(
            "SLIStatus",
            {
                "MEETING": "meeting",
                "AT_RISK": "at_risk",
                "BREACHING": "breaching",
            },
        ),
        "validation_result": EnumDef(
            "ValidationResult",
            {
                "VALID": "valid",
                "MISCONFIGURED": "misconfigured",
                "STALE": "stale",
            },
        ),
    },
    record_fields=[
        FieldDef("target_value", float, 99.9),
        FieldDef("actual_value", float, 0.0),
    ],
)

# Backward-compatible re-exports
SLIType = ServiceLevelIndicatorEngine.SLIType
SLIStatus = ServiceLevelIndicatorEngine.SLIStatus
ValidationResult = ServiceLevelIndicatorEngine.ValidationResult
ServiceLevelIndicatorRecord = ServiceLevelIndicatorEngine.Record
ServiceLevelIndicatorAnalysis = ServiceLevelIndicatorEngine.Analysis
ServiceLevelIndicatorReport = ServiceLevelIndicatorEngine.Report
