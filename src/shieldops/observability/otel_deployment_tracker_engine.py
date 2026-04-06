"""OtelDeploymentTrackerEngine — Track OTel Collector deployment lifecycle across clusters."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

OtelDeploymentTrackerEngine = engine(
    "OtelDeploymentTrackerEngine",
    description="Track OTel Collector deployment lifecycle across clusters.",
    enums={
        "deployment_phase": EnumDef(
            "DeploymentPhase",
            {
                "PLANNED": "planned",
                "DEPLOYING": "deploying",
                "RUNNING": "running",
                "DEGRADED": "degraded",
                "FAILED": "failed",
            },
        ),
        "deployment_type": EnumDef(
            "DeploymentType",
            {
                "DAEMONSET": "daemonset",
                "DEPLOYMENT": "deployment",
                "SIDECAR": "sidecar",
            },
        ),
        "cluster_region": EnumDef(
            "ClusterRegion",
            {
                "US_EAST": "us_east",
                "US_WEST": "us_west",
                "EU_WEST": "eu_west",
                "AP_SOUTH": "ap_south",
            },
        ),
    },
    record_fields=[
        FieldDef("replica_count", int, 0),
        FieldDef("config_version", str, ""),
    ],
)

# Backward-compatible re-exports
DeploymentPhase = OtelDeploymentTrackerEngine.DeploymentPhase
DeploymentType = OtelDeploymentTrackerEngine.DeploymentType
ClusterRegion = OtelDeploymentTrackerEngine.ClusterRegion
OtelDeploymentTrackerRecord = OtelDeploymentTrackerEngine.Record
OtelDeploymentTrackerAnalysis = OtelDeploymentTrackerEngine.Analysis
OtelDeploymentTrackerReport = OtelDeploymentTrackerEngine.Report
