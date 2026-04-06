"""EnvironmentLifecycleEngine Environment lifecycle management, provisioning tracking, TTL enf..."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

EnvironmentLifecycleEngine = engine(
    "EnvironmentLifecycleEngine",
    module="operations",  # uses record_item
    description="Environment lifecycle management with TTL enforcement.",
    enums={
        "environment_stage": EnumDef(
            "EnvironmentStage",
            {
                "REQUESTED": "requested",
                "PROVISIONING": "provisioning",
                "ACTIVE": "active",
                "HIBERNATING": "hibernating",
                "DECOMMISSIONED": "decommissioned",
            },
        ),
        "environment_purpose": EnumDef(
            "EnvironmentPurpose",
            {
                "DEVELOPMENT": "development",
                "TESTING": "testing",
                "STAGING": "staging",
                "PREVIEW": "preview",
                "PRODUCTION": "production",
            },
        ),
        "lifecycle_action": EnumDef(
            "LifecycleAction",
            {
                "CREATE": "create",
                "SCALE": "scale",
                "HIBERNATE": "hibernate",
                "WAKE": "wake",
                "DESTROY": "destroy",
            },
        ),
    },
)

# Backward-compatible re-exports
EnvironmentStage = EnvironmentLifecycleEngine.EnvironmentStage
EnvironmentPurpose = EnvironmentLifecycleEngine.EnvironmentPurpose
LifecycleAction = EnvironmentLifecycleEngine.LifecycleAction
EnvironmentLifecycleRecord = EnvironmentLifecycleEngine.Record
EnvironmentLifecycleAnalysis = EnvironmentLifecycleEngine.Analysis
EnvironmentLifecycleReport = EnvironmentLifecycleEngine.Report
