"""Access Hygiene Analytics — permission drift."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

AccessHygieneAnalytics = engine(
    "AccessHygieneAnalytics",
    description="Analyze access hygiene and drift.",
    enums={
        "metric": EnumDef(
            "HygieneMetric",
            {
                "UNUSED_PERMISSIONS": "unused_permissions",
                "STALE_ACCOUNTS": "stale_accounts",
                "EXCESSIVE_ROLES": "excessive_roles",
                "SHARED_CREDENTIALS": "shared_credentials",
                "ORPHANED_ACCESS": "orphaned_access",
            },
        ),
        "drift": EnumDef(
            "DriftRate",
            {
                "NONE": "none",
                "SLOW": "slow",
                "MODERATE": "moderate",
                "RAPID": "rapid",
                "CRITICAL": "critical",
            },
        ),
        "cleanup": EnumDef(
            "CleanupRate",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "FAIR": "fair",
                "POOR": "poor",
                "NEGLIGIBLE": "negligible",
            },
        ),
    },
    record_fields=[
        FieldDef("permission_count", int, 0),
        FieldDef("unused_count", int, 0),
        FieldDef("days_inactive", int, 0),
    ],
    key_field="identity_id",
)

# Backward-compatible re-exports
HygieneMetric = AccessHygieneAnalytics.HygieneMetric
DriftRate = AccessHygieneAnalytics.DriftRate
CleanupRate = AccessHygieneAnalytics.CleanupRate
AccessHygieneRecord = AccessHygieneAnalytics.Record
AccessHygieneAnalysis = AccessHygieneAnalytics.Analysis
AccessHygieneReport = AccessHygieneAnalytics.Report
