"""Fix Velocity Analytics — remediation speed."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

FixVelocityAnalytics = engine(
    "FixVelocityAnalytics",
    description="Analyze fix velocity and throughput.",
    enums={
        "metric": EnumDef(
            "VelocityMetric",
            {
                "TIME_TO_DETECT": "time_to_detect",
                "TIME_TO_REMEDIATE": "time_to_remediate",
                "TIME_TO_VERIFY": "time_to_verify",
                "QUEUE_WAIT": "queue_wait",
                "TOTAL_CYCLE": "total_cycle",
            },
        ),
        "stage": EnumDef(
            "StageTime",
            {
                "FAST": "fast",
                "NORMAL": "normal",
                "SLOW": "slow",
                "BLOCKED": "blocked",
                "UNKNOWN": "unknown",
            },
        ),
        "throughput": EnumDef(
            "ThroughputRate",
            {
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "STALLED": "stalled",
                "RAMPING": "ramping",
            },
        ),
    },
    record_fields=[
        FieldDef("duration_sec", float, 0.0),
        FieldDef("queue_depth", int, 0),
        FieldDef("automated", bool, False),
    ],
    key_field="remediation_id",
)

# Backward-compatible re-exports
VelocityMetric = FixVelocityAnalytics.VelocityMetric
StageTime = FixVelocityAnalytics.StageTime
ThroughputRate = FixVelocityAnalytics.ThroughputRate
FixVelocityRecord = FixVelocityAnalytics.Record
FixVelocityAnalysis = FixVelocityAnalytics.Analysis
FixVelocityReport = FixVelocityAnalytics.Report
