"""Service Latency Decomposition Engine — decompose end-to-end latency by service, identify la..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ServiceLatencyDecompositionEngine = engine(
    "ServiceLatencyDecompositionEngine",
    description="Decompose end-to-end latency by service, identify latency hotspots, forecas...",
    enums={
        "latency_component": EnumDef(
            "LatencyComponent",
            {
                "PROCESSING": "processing",
                "NETWORK": "network",
                "QUEUE": "queue",
                "SERIALIZATION": "serialization",
            },
        ),
        "decomposition_method": EnumDef(
            "DecompositionMethod",
            {
                "WATERFALL": "waterfall",
                "CRITICAL_PATH": "critical_path",
                "PERCENTILE": "percentile",
                "HISTOGRAM": "histogram",
            },
        ),
        "latency_trend": EnumDef(
            "LatencyTrend",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DEGRADING": "degrading",
                "VOLATILE": "volatile",
            },
        ),
    },
    record_fields=[
        FieldDef("operation_name", str, ""),
        FieldDef("total_latency_ms", float, 0.0),
        FieldDef("component_latency_ms", float, 0.0),
        FieldDef("p99_latency_ms", float, 0.0),
        FieldDef("sample_count", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="service_name",
)

# Backward-compatible re-exports
LatencyComponent = ServiceLatencyDecompositionEngine.LatencyComponent
DecompositionMethod = ServiceLatencyDecompositionEngine.DecompositionMethod
LatencyTrend = ServiceLatencyDecompositionEngine.LatencyTrend
ServiceLatencyRecord = ServiceLatencyDecompositionEngine.Record
ServiceLatencyAnalysis = ServiceLatencyDecompositionEngine.Analysis
ServiceLatencyReport = ServiceLatencyDecompositionEngine.Report
