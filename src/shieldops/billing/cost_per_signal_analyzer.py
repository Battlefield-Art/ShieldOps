"""Cost Per Signal Analyzer — cost-per-signal analysis for observability spend optimization."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

CostPerSignalAnalyzer = engine(
    "CostPerSignalAnalyzer",
    description="Cost Per Signal Analyzer — cost-per-signal analysis for observability spend...",
    enums={
        "signal_type": EnumDef(
            "SignalType",
            {
                "METRIC": "metric",
                "LOG": "log",
                "TRACE": "trace",
                "PROFILE": "profile",
                "EVENT": "event",
            },
        ),
        "cost_source": EnumDef(
            "CostSource",
            {
                "VENDOR_BILLING": "vendor_billing",
                "USAGE_API": "usage_api",
                "ESTIMATED": "estimated",
                "METERED": "metered",
                "CUSTOM": "custom",
            },
        ),
        "cost_efficiency": EnumDef(
            "CostEfficiency",
            {
                "OPTIMAL": "optimal",
                "ACCEPTABLE": "acceptable",
                "OVERPRICED": "overpriced",
                "WASTEFUL": "wasteful",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
SignalType = CostPerSignalAnalyzer.SignalType
CostSource = CostPerSignalAnalyzer.CostSource
CostEfficiency = CostPerSignalAnalyzer.CostEfficiency
CostSignalRecord = CostPerSignalAnalyzer.Record
CostSignalAnalysis = CostPerSignalAnalyzer.Analysis
CostPerSignalReport = CostPerSignalAnalyzer.Report
