"""Service Mesh Latency Profiler. Profile hop latency, identify proxy overhead, and detect lat..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ServiceMeshLatencyProfiler = engine(
    "ServiceMeshLatencyProfiler",
    description="Profile hop latency, identify proxy overhead, detect latency regressions.",
    enums={
        "latency_source": EnumDef(
            "LatencySource",
            {
                "APPLICATION": "application",
                "PROXY": "proxy",
                "NETWORK": "network",
                "QUEUE": "queue",
            },
        ),
        "hop_type": EnumDef(
            "HopType",
            {
                "INGRESS": "ingress",
                "SERVICE_TO_SERVICE": "service_to_service",
                "EGRESS": "egress",
                "EXTERNAL": "external",
            },
        ),
        "regression_severity": EnumDef(
            "RegressionSeverity",
            {
                "CRITICAL": "critical",
                "MAJOR": "major",
                "MINOR": "minor",
                "NEGLIGIBLE": "negligible",
            },
        ),
    },
    record_fields=[
        FieldDef("latency_ms", float, 0.0),
        FieldDef("baseline_ms", float, 0.0),
        FieldDef("proxy_overhead_ms", float, 0.0),
    ],
    key_field="hop_name",
)

# Backward-compatible re-exports
LatencySource = ServiceMeshLatencyProfiler.LatencySource
HopType = ServiceMeshLatencyProfiler.HopType
RegressionSeverity = ServiceMeshLatencyProfiler.RegressionSeverity
MeshLatencyRecord = ServiceMeshLatencyProfiler.Record
MeshLatencyAnalysis = ServiceMeshLatencyProfiler.Analysis
MeshLatencyReport = ServiceMeshLatencyProfiler.Report
