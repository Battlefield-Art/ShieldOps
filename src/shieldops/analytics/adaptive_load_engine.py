"""AdaptiveLoadEngine — adaptive load engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AdaptiveLoadEngine = engine(
    "AdaptiveLoadEngine",
    description="Adaptive Load Engine.",
    enums={
        "load_pattern": EnumDef(
            "LoadPattern",
            {
                "STEADY": "steady",
                "SPIKE": "spike",
                "RAMP": "ramp",
                "WAVE": "wave",
                "RANDOM": "random",
            },
        ),
        "adaptation_strategy": EnumDef(
            "AdaptationStrategy",
            {
                "SCALE_UP": "scale_up",
                "SCALE_OUT": "scale_out",
                "SHED_LOAD": "shed_load",
                "RATE_LIMIT": "rate_limit",
                "QUEUE_BUFFER": "queue_buffer",
            },
        ),
        "load_severity": EnumDef(
            "LoadSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
                "NORMAL": "normal",
            },
        ),
    },
)

# Backward-compatible re-exports
LoadPattern = AdaptiveLoadEngine.LoadPattern
AdaptationStrategy = AdaptiveLoadEngine.AdaptationStrategy
LoadSeverity = AdaptiveLoadEngine.LoadSeverity
AdaptiveLoadRecord = AdaptiveLoadEngine.Record
AdaptiveLoadAnalysis = AdaptiveLoadEngine.Analysis
AdaptiveLoadReport = AdaptiveLoadEngine.Report
