"""Mesh Control Plane Observer. Monitor config propagation, assess control plane health, and d..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

MeshControlPlaneObserver = engine(
    "MeshControlPlaneObserver",
    description="Monitor config propagation, assess control plane health, detect sync diverg...",
    enums={
        "propagation_status": EnumDef(
            "PropagationStatus",
            {
                "CONVERGED": "converged",
                "PROPAGATING": "propagating",
                "STALE": "stale",
                "FAILED": "failed",
            },
        ),
        "control_plane_health": EnumDef(
            "ControlPlaneHealth",
            {
                "HEALTHY": "healthy",
                "DEGRADED": "degraded",
                "CRITICAL": "critical",
                "UNKNOWN": "unknown",
            },
        ),
        "sync_state": EnumDef(
            "SyncState",
            {
                "IN_SYNC": "in_sync",
                "LAGGING": "lagging",
                "DIVERGED": "diverged",
                "DISCONNECTED": "disconnected",
            },
        ),
    },
    record_fields=[
        FieldDef("component", str, ""),
        FieldDef("config_version", str, ""),
        FieldDef("latency_ms", float, 0.0),
        FieldDef("node_count", int, 0),
    ],
    key_field="mesh_name",
)

# Backward-compatible re-exports
PropagationStatus = MeshControlPlaneObserver.PropagationStatus
ControlPlaneHealth = MeshControlPlaneObserver.ControlPlaneHealth
SyncState = MeshControlPlaneObserver.SyncState
ControlPlaneRecord = MeshControlPlaneObserver.Record
ControlPlaneAnalysis = MeshControlPlaneObserver.Analysis
ControlPlaneReport = MeshControlPlaneObserver.Report
