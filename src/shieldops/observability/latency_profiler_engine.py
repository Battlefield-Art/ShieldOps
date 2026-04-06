"""LatencyProfilerEngine — Profile and analyze service latency patterns."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

LatencyProfilerEngine = engine(
    "LatencyProfilerEngine",
    description="Profile and analyze service latency patterns.",
    enums={
        "latency_bucket": EnumDef(
            "LatencyBucket",
            {
                "P50": "p50",
                "P90": "p90",
                "P95": "p95",
                "P99": "p99",
                "MAX": "max",
            },
        ),
        "service_tier": EnumDef(
            "ServiceTier",
            {
                "CRITICAL": "critical",
                "STANDARD": "standard",
                "BACKGROUND": "background",
                "BATCH": "batch",
                "INTERNAL": "internal",
            },
        ),
        "bottleneck_source": EnumDef(
            "BottleneckSource",
            {
                "DATABASE": "database",
                "EXTERNAL_API": "external_api",
                "CACHE_MISS": "cache_miss",
                "CPU": "cpu",
                "NETWORK": "network",
            },
        ),
    },
    record_fields=[
        FieldDef("latency_ms", float, 0.0),
        FieldDef("request_count", int, 0),
        FieldDef("error_rate", float, 0.0),
    ],
)

# Backward-compatible re-exports
LatencyBucket = LatencyProfilerEngine.LatencyBucket
ServiceTier = LatencyProfilerEngine.ServiceTier
BottleneckSource = LatencyProfilerEngine.BottleneckSource
LatencyProfilerRecord = LatencyProfilerEngine.Record
LatencyProfilerAnalysis = LatencyProfilerEngine.Analysis
LatencyProfilerReport = LatencyProfilerEngine.Report
