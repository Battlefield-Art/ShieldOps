"""Multi Region Failover Automator — multi-region failover automation and coordination."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

MultiRegionFailoverAutomator = engine(
    "MultiRegionFailoverAutomator",
    description="Multi Region Failover Automator — multi-region failover automation and coor...",
    enums={
        "failover_type": EnumDef(
            "FailoverType",
            {
                "ACTIVE_PASSIVE": "active_passive",
                "ACTIVE_ACTIVE": "active_active",
                "PILOT_LIGHT": "pilot_light",
                "WARM_STANDBY": "warm_standby",
                "MULTI_SITE": "multi_site",
            },
        ),
        "failover_trigger": EnumDef(
            "FailoverTrigger",
            {
                "HEALTH_CHECK": "health_check",
                "REGION_OUTAGE": "region_outage",
                "DEGRADATION": "degradation",
                "SCHEDULED": "scheduled",
                "MANUAL": "manual",
            },
        ),
        "failover_status": EnumDef(
            "FailoverStatus",
            {
                "COMPLETED": "completed",
                "IN_PROGRESS": "in_progress",
                "FAILED": "failed",
                "PARTIAL": "partial",
                "ROLLED_BACK": "rolled_back",
            },
        ),
    },
)

# Backward-compatible re-exports
FailoverType = MultiRegionFailoverAutomator.FailoverType
FailoverTrigger = MultiRegionFailoverAutomator.FailoverTrigger
FailoverStatus = MultiRegionFailoverAutomator.FailoverStatus
FailoverRecord = MultiRegionFailoverAutomator.Record
FailoverAnalysis = MultiRegionFailoverAutomator.Analysis
MultiRegionFailoverReport = MultiRegionFailoverAutomator.Report
