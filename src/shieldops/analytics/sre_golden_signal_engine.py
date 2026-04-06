"""SRE Golden Signal Engine compute golden signal health, detect signal anomalies, rank servic..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SreGoldenSignalEngine = engine(
    "SreGoldenSignalEngine",
    description="Compute golden signal health, detect signal anomalies, rank services by sig...",
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
        "signal_status": EnumDef(
            "SignalStatus",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "CRITICAL": "critical",
                "UNKNOWN": "unknown",
            },
        ),
        "service_tier": EnumDef(
            "ServiceTier",
            {
                "TIER1": "tier1",
                "TIER2": "tier2",
                "TIER3": "tier3",
                "TIER4": "tier4",
            },
        ),
    },
    record_fields=[
        FieldDef("value", float, 0.0),
        FieldDef("threshold", float, 100.0),
        FieldDef("baseline", float, 0.0),
        FieldDef("region", str, ""),
        FieldDef("description", str, ""),
    ],
    key_field="service_id",
)

# Backward-compatible re-exports
GoldenSignal = SreGoldenSignalEngine.GoldenSignal
SignalStatus = SreGoldenSignalEngine.SignalStatus
ServiceTier = SreGoldenSignalEngine.ServiceTier
GoldenSignalRecord = SreGoldenSignalEngine.Record
GoldenSignalAnalysis = SreGoldenSignalEngine.Analysis
GoldenSignalReport = SreGoldenSignalEngine.Report
