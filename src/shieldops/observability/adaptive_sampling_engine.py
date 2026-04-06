"""AdaptiveSamplingEngine — adaptive sampling engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AdaptiveSamplingEngine = engine(
    "AdaptiveSamplingEngine",
    module="operations",  # uses record_item
    description="Adaptive Sampling Engine.",
    enums={
        "sampling_strategy": EnumDef(
            "SamplingStrategy",
            {
                "HEAD_BASED": "head_based",
                "TAIL_BASED": "tail_based",
                "PRIORITY_BASED": "priority_based",
                "DYNAMIC": "dynamic",
                "HYBRID": "hybrid",
            },
        ),
        "traffic_pattern": EnumDef(
            "TrafficPattern",
            {
                "NORMAL": "normal",
                "SPIKE": "spike",
                "DEGRADED": "degraded",
                "INCIDENT": "incident",
                "MAINTENANCE": "maintenance",
            },
        ),
        "sample_decision": EnumDef(
            "SampleDecision",
            {
                "KEEP": "keep",
                "DROP": "drop",
                "DEFER": "defer",
                "PRIORITY_KEEP": "priority_keep",
                "FORCE_KEEP": "force_keep",
            },
        ),
    },
)

# Backward-compatible re-exports
SamplingStrategy = AdaptiveSamplingEngine.SamplingStrategy
TrafficPattern = AdaptiveSamplingEngine.TrafficPattern
SampleDecision = AdaptiveSamplingEngine.SampleDecision
AdaptiveSamplingEngineRecord = AdaptiveSamplingEngine.Record
AdaptiveSamplingEngineAnalysis = AdaptiveSamplingEngine.Analysis
AdaptiveSamplingEngineReport = AdaptiveSamplingEngine.Report
