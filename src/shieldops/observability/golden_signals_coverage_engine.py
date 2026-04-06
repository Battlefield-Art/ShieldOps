"""GoldenSignalsCoverageEngine — Track coverage of four golden signals per service."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

GoldenSignalsCoverageEngine = engine(
    "GoldenSignalsCoverageEngine",
    description="Track coverage of the four golden signals (latency, traffic, errors, satura...",
    enums={
        "golden_signal": EnumDef(
            "GoldenSignal",
            {
                "LATENCY": "latency",
                "TRAFFIC": "traffic",
                "ERRORS": "errors",
                "SATURATION": "saturation",
            },
        ),
        "coverage_status": EnumDef(
            "CoverageStatus",
            {
                "COVERED": "covered",
                "PARTIAL": "partial",
                "MISSING": "missing",
            },
        ),
        "signal_quality": EnumDef(
            "SignalQuality",
            {
                "EXCELLENT": "excellent",
                "ADEQUATE": "adequate",
                "INSUFFICIENT": "insufficient",
            },
        ),
    },
    record_fields=[
        FieldDef("metric_count", int, 0),
        FieldDef("alert_configured", bool, False),
    ],
)

# Backward-compatible re-exports
GoldenSignal = GoldenSignalsCoverageEngine.GoldenSignal
CoverageStatus = GoldenSignalsCoverageEngine.CoverageStatus
SignalQuality = GoldenSignalsCoverageEngine.SignalQuality
GoldenSignalsCoverageRecord = GoldenSignalsCoverageEngine.Record
GoldenSignalsCoverageAnalysis = GoldenSignalsCoverageEngine.Analysis
GoldenSignalsCoverageReport = GoldenSignalsCoverageEngine.Report
