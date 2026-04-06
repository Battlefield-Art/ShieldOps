"""SecurityPostureTrend -- track posture trends."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SecurityPostureTrendEngine = engine(
    "SecurityPostureTrendEngine",
    description="Track security posture trends over time.",
    enums={
        "period": EnumDef(
            "TrendPeriod",
            {
                "DAILY": "daily",
                "WEEKLY": "weekly",
                "MONTHLY": "monthly",
                "QUARTERLY": "quarterly",
            },
        ),
        "change": EnumDef(
            "PostureChange",
            {
                "IMPROVING": "improving",
                "STABLE": "stable",
                "DEGRADING": "degrading",
                "VOLATILE": "volatile",
            },
        ),
        "driver": EnumDef(
            "DriverCategory",
            {
                "PATCH_MANAGEMENT": "patch_management",
                "CONFIG_DRIFT": "config_drift",
                "NEW_THREATS": "new_threats",
                "STAFF_CHANGE": "staff_change",
                "TOOL_DEPLOYMENT": "tool_deployment",
            },
        ),
    },
    record_fields=[
        FieldDef("domain", str, ""),
    ],
)

# Backward-compatible re-exports
TrendPeriod = SecurityPostureTrendEngine.TrendPeriod
PostureChange = SecurityPostureTrendEngine.PostureChange
DriverCategory = SecurityPostureTrendEngine.DriverCategory
SecurityPostureTrendRecord = SecurityPostureTrendEngine.Record
SecurityPostureTrendAnalysis = SecurityPostureTrendEngine.Analysis
SecurityPostureTrendReport = SecurityPostureTrendEngine.Report
