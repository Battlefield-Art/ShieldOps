"""FleetIntelligenceEngine — Aggregate intelligence across the entire agent fleet."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

FleetIntelligenceEngine = engine(
    "FleetIntelligenceEngine",
    description="Aggregate intelligence across the entire agent fleet engine.",
    enums={
        "fleet_metric": EnumDef(
            "FleetMetric",
            {
                "TOTAL_INVOCATIONS": "total_invocations",
                "SUCCESS_RATE": "success_rate",
                "AVG_LATENCY": "avg_latency",
                "COST_PER_RESOLUTION": "cost_per_resolution",
            },
        ),
        "fleet_health": EnumDef(
            "FleetHealth",
            {
                "THRIVING": "thriving",
                "STABLE": "stable",
                "DECLINING": "declining",
                "CRITICAL": "critical",
            },
        ),
        "strategic_insight": EnumDef(
            "StrategicInsight",
            {
                "SCALE_UP": "scale_up",
                "OPTIMIZE": "optimize",
                "CONSOLIDATE": "consolidate",
                "RETRAIN": "retrain",
            },
        ),
    },
    record_fields=[
        FieldDef("invocations", int, 0),
        FieldDef("success_count", int, 0),
        FieldDef("failure_count", int, 0),
        FieldDef("avg_latency_ms", float, 0.0),
        FieldDef("cost", float, 0.0),
    ],
)

# Backward-compatible re-exports
FleetMetric = FleetIntelligenceEngine.FleetMetric
FleetHealth = FleetIntelligenceEngine.FleetHealth
StrategicInsight = FleetIntelligenceEngine.StrategicInsight
FleetIntelligenceRecord = FleetIntelligenceEngine.Record
FleetIntelligenceAnalysis = FleetIntelligenceEngine.Analysis
FleetIntelligenceReport = FleetIntelligenceEngine.Report
