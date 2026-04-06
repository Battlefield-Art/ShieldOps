"""Patch Compliance Analytics — patch posture."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

PatchComplianceAnalytics = engine(
    "PatchComplianceAnalytics",
    description="Analyze patch compliance posture.",
    enums={
        "window": EnumDef(
            "ComplianceWindow",
            {
                "WITHIN_SLA": "within_sla",
                "APPROACHING": "approaching",
                "OVERDUE": "overdue",
                "CRITICAL_OVERDUE": "critical_overdue",
                "EXEMPT": "exempt",
            },
        ),
        "age": EnumDef(
            "PatchAge",
            {
                "CURRENT": "current",
                "RECENT": "recent",
                "STALE": "stale",
                "OUTDATED": "outdated",
                "ANCIENT": "ancient",
            },
        ),
        "exposure": EnumDef(
            "RiskExposure",
            {
                "NONE": "none",
                "LOW": "low",
                "MEDIUM": "medium",
                "HIGH": "high",
                "CRITICAL": "critical",
            },
        ),
    },
    record_fields=[
        FieldDef("patch_id", str, ""),
        FieldDef("days_since_release", int, 0),
        FieldDef("applied", bool, False),
    ],
    key_field="asset_id",
)

# Backward-compatible re-exports
ComplianceWindow = PatchComplianceAnalytics.ComplianceWindow
PatchAge = PatchComplianceAnalytics.PatchAge
RiskExposure = PatchComplianceAnalytics.RiskExposure
PatchComplianceRecord = PatchComplianceAnalytics.Record
PatchComplianceAnalysis = PatchComplianceAnalytics.Analysis
PatchComplianceReport = PatchComplianceAnalytics.Report
