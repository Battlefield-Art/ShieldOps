"""SloAwareSamplingEngine — adjust telemetry sampling rates based on SLO burn rate."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SloAwareSamplingEngine = engine(
    "SloAwareSamplingEngine",
    description="SLO-Aware Sampling Engine — sample more when SLOs are at risk, less when he...",
    enums={
        "slo_status": EnumDef(
            "SLOStatus",
            {
                "HEALTHY": "healthy",
                "BURNING": "burning",
                "CRITICAL": "critical",
                "BREACHED": "breached",
            },
        ),
        "sampling_adjustment": EnumDef(
            "SamplingAdjustment",
            {
                "INCREASE": "increase",
                "MAINTAIN": "maintain",
                "DECREASE": "decrease",
                "FULL_CAPTURE": "full_capture",
            },
        ),
        "burn_rate_window": EnumDef(
            "BurnRateWindow",
            {
                "FAST_1H": "fast_1h",
                "SLOW_6H": "slow_6h",
                "MEDIUM_24H": "medium_24h",
                "LONG_7D": "long_7d",
            },
        ),
    },
    record_fields=[
        FieldDef("burn_rate", float, 0.0),
        FieldDef("sampling_rate", float, 1.0),
    ],
)

# Backward-compatible re-exports
SLOStatus = SloAwareSamplingEngine.SLOStatus
SamplingAdjustment = SloAwareSamplingEngine.SamplingAdjustment
BurnRateWindow = SloAwareSamplingEngine.BurnRateWindow
SloAwareSamplingRecord = SloAwareSamplingEngine.Record
SloAwareSamplingAnalysis = SloAwareSamplingEngine.Analysis
SloAwareSamplingReport = SloAwareSamplingEngine.Report
