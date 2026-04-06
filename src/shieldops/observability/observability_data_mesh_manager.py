"""ObservabilityDataMeshManager — observability data mesh manager."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

ObservabilityDataMeshManager = engine(
    "ObservabilityDataMeshManager",
    module="operations",  # uses record_item
    description="Observability Data Mesh Manager.",
    enums={
        "mesh_domain": EnumDef(
            "MeshDomain",
            {
                "INFRASTRUCTURE": "infrastructure",
                "APPLICATION": "application",
                "SECURITY": "security",
                "BUSINESS": "business",
                "PLATFORM": "platform",
            },
        ),
        "data_product": EnumDef(
            "DataProduct",
            {
                "METRICS": "metrics",
                "LOGS": "logs",
                "TRACES": "traces",
                "DASHBOARDS": "dashboards",
                "ALERTS": "alerts",
            },
        ),
        "mesh_maturity": EnumDef(
            "MeshMaturity",
            {
                "FOUNDATIONAL": "foundational",
                "MANAGED": "managed",
                "OPTIMIZED": "optimized",
                "AUTONOMOUS": "autonomous",
                "INNOVATIVE": "innovative",
            },
        ),
    },
)

# Backward-compatible re-exports
MeshDomain = ObservabilityDataMeshManager.MeshDomain
DataProduct = ObservabilityDataMeshManager.DataProduct
MeshMaturity = ObservabilityDataMeshManager.MeshMaturity
ObservabilityDataMeshManagerRecord = ObservabilityDataMeshManager.Record
ObservabilityDataMeshManagerAnalysis = ObservabilityDataMeshManager.Analysis
ObservabilityDataMeshManagerReport = ObservabilityDataMeshManager.Report
