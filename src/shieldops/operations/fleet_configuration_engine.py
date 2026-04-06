"""FleetConfigurationEngine Multi-cluster configuration management, fleet-wide policy enforcem..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

FleetConfigurationEngine = engine(
    "FleetConfigurationEngine",
    module="operations",  # uses record_item
    description="Multi-cluster configuration management with fleet-wide policy enforcement.",
    enums={
        "config_scope": EnumDef(
            "ConfigScope",
            {
                "CLUSTER": "cluster",
                "NAMESPACE": "namespace",
                "WORKLOAD": "workload",
                "NODE_POOL": "node_pool",
                "FLEET_WIDE": "fleet_wide",
            },
        ),
        "propagation_status": EnumDef(
            "PropagationStatus",
            {
                "PENDING": "pending",
                "PROPAGATING": "propagating",
                "APPLIED": "applied",
                "FAILED": "failed",
                "PARTIAL": "partial",
            },
        ),
        "policy_enforcement": EnumDef(
            "PolicyEnforcement",
            {
                "ENFORCED": "enforced",
                "AUDIT": "audit",
                "WARN": "warn",
                "DISABLED": "disabled",
                "PENDING_REVIEW": "pending_review",
            },
        ),
    },
    record_fields=[
        FieldDef("config_key", str, ""),
        FieldDef("target_clusters", int, 0),
        FieldDef("applied_clusters", int, 0),
        FieldDef("failed_clusters", int, 0),
        FieldDef("propagation_time_seconds", float, 0.0),
        FieldDef("config_version", str, ""),
    ],
)

# Backward-compatible re-exports
ConfigScope = FleetConfigurationEngine.ConfigScope
PropagationStatus = FleetConfigurationEngine.PropagationStatus
PolicyEnforcement = FleetConfigurationEngine.PolicyEnforcement
FleetConfigurationRecord = FleetConfigurationEngine.Record
FleetConfigurationAnalysis = FleetConfigurationEngine.Analysis
FleetConfigurationReport = FleetConfigurationEngine.Report
