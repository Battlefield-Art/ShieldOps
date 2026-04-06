"""Fleet Management Optimizer — fleet management optimization across compute resources."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

FleetManagementOptimizer = engine(
    "FleetManagementOptimizer",
    description="Fleet Management Optimizer — fleet management optimization across compute r...",
    enums={
        "fleet_type": EnumDef(
            "FleetType",
            {
                "EC2_FLEET": "ec2_fleet",
                "K8S_CLUSTER": "k8s_cluster",
                "CONTAINER_FLEET": "container_fleet",
                "VM_SCALE_SET": "vm_scale_set",
                "SERVERLESS": "serverless",
            },
        ),
        "optimization_action": EnumDef(
            "OptimizationAction",
            {
                "RIGHT_SIZE": "right_size",
                "REBALANCE": "rebalance",
                "CONSOLIDATE": "consolidate",
                "MODERNIZE": "modernize",
                "MIGRATE": "migrate",
            },
        ),
        "fleet_health": EnumDef(
            "FleetHealth",
            {
                "OPTIMAL": "optimal",
                "GOOD": "good",
                "SUBOPTIMAL": "suboptimal",
                "DEGRADED": "degraded",
                "CRITICAL": "critical",
            },
        ),
    },
)

# Backward-compatible re-exports
FleetType = FleetManagementOptimizer.FleetType
OptimizationAction = FleetManagementOptimizer.OptimizationAction
FleetHealth = FleetManagementOptimizer.FleetHealth
FleetRecord = FleetManagementOptimizer.Record
FleetAnalysis = FleetManagementOptimizer.Analysis
FleetManagementReport = FleetManagementOptimizer.Report
