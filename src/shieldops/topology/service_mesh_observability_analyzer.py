"""Service Mesh Observability Analyzer service mesh observability analysis and traffic insights."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ServiceMeshObservabilityAnalyzer = engine(
    "ServiceMeshObservabilityAnalyzer",
    description="Service Mesh Observability Analyzer service mesh observability analysis and...",
    enums={
        "mesh_component": EnumDef(
            "MeshComponent",
            {
                "SIDECAR": "sidecar",
                "CONTROL_PLANE": "control_plane",
                "DATA_PLANE": "data_plane",
                "GATEWAY": "gateway",
                "POLICY_ENGINE": "policy_engine",
            },
        ),
        "mesh_source": EnumDef(
            "MeshSource",
            {
                "ISTIO": "istio",
                "LINKERD": "linkerd",
                "CONSUL_CONNECT": "consul_connect",
                "ENVOY": "envoy",
                "CUSTOM": "custom",
            },
        ),
        "mesh_health": EnumDef(
            "MeshHealth",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "PARTIAL": "partial",
                "FAILING": "failing",
                "UNKNOWN": "unknown",
            },
        ),
    },
)

# Backward-compatible re-exports
MeshComponent = ServiceMeshObservabilityAnalyzer.MeshComponent
MeshSource = ServiceMeshObservabilityAnalyzer.MeshSource
MeshHealth = ServiceMeshObservabilityAnalyzer.MeshHealth
MeshRecord = ServiceMeshObservabilityAnalyzer.Record
MeshAnalysis = ServiceMeshObservabilityAnalyzer.Analysis
ServiceMeshObservabilityReport = ServiceMeshObservabilityAnalyzer.Report
