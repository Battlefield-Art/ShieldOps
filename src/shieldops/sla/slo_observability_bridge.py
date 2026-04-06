"""Slo Observability Bridge — SLO-observability bridge connecting SLIs to telemetry."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

SloObservabilityBridge = engine(
    "SloObservabilityBridge",
    description="Slo Observability Bridge — SLO-observability bridge connecting SLIs to tele...",
    enums={
        "sli_mapping": EnumDef(
            "SLIMapping",
            {
                "ERROR_RATE": "error_rate",
                "LATENCY_P99": "latency_p99",
                "AVAILABILITY": "availability",
                "THROUGHPUT": "throughput",
                "SATURATION": "saturation",
            },
        ),
        "bridge_source": EnumDef(
            "BridgeSource",
            {
                "PROMETHEUS_RULES": "prometheus_rules",
                "DATADOG_MONITORS": "datadog_monitors",
                "CUSTOM_QUERY": "custom_query",
                "OTEL_METRIC": "otel_metric",
                "DERIVED": "derived",
            },
        ),
        "mapping_quality": EnumDef(
            "MappingQuality",
            {
                "PRECISE": "precise",
                "APPROXIMATE": "approximate",
                "ESTIMATED": "estimated",
                "MISSING": "missing",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
SLIMapping = SloObservabilityBridge.SLIMapping
BridgeSource = SloObservabilityBridge.BridgeSource
MappingQuality = SloObservabilityBridge.MappingQuality
SLOBridgeRecord = SloObservabilityBridge.Record
SLOBridgeAnalysis = SloObservabilityBridge.Analysis
SloObservabilityReport = SloObservabilityBridge.Report
