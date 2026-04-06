"""Config Drift Tracker Engine — track infrastructure configuration drift."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

ConfigDriftTrackerEngine = engine(
    "ConfigDriftTrackerEngine",
    description="Track infrastructure configuration drift and remediation.",
    enums={
        "drift_source": EnumDef(
            "DriftSource",
            {
                "KUBERNETES": "kubernetes",
                "TERRAFORM": "terraform",
                "HELM": "helm",
                "CLOUD_CONSOLE": "cloud_console",
                "CI_CD": "ci_cd",
            },
        ),
        "drift_category": EnumDef(
            "DriftCategory",
            {
                "SECURITY": "security",
                "PERFORMANCE": "performance",
                "COMPLIANCE": "compliance",
                "OPERATIONAL": "operational",
                "COSMETIC": "cosmetic",
            },
        ),
        "remediation_method": EnumDef(
            "RemediationMethod",
            {
                "AUTO_REVERT": "auto_revert",
                "MANUAL_FIX": "manual_fix",
                "ACCEPT": "accept",
                "BASELINE_UPDATE": "baseline_update",
                "ESCALATE": "escalate",
            },
        ),
    },
    record_fields=[
        FieldDef("service_id", str, ""),
        FieldDef("drift_field", str, ""),
        FieldDef("expected_value", str, ""),
        FieldDef("actual_value", str, ""),
        FieldDef("drift_detected_at", float, 0.0),
        FieldDef("remediated_at", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="resource_id",
)

# Backward-compatible re-exports
DriftSource = ConfigDriftTrackerEngine.DriftSource
DriftCategory = ConfigDriftTrackerEngine.DriftCategory
RemediationMethod = ConfigDriftTrackerEngine.RemediationMethod
ConfigDriftTrackerRecord = ConfigDriftTrackerEngine.Record
ConfigDriftTrackerAnalysis = ConfigDriftTrackerEngine.Analysis
ConfigDriftTrackerReport = ConfigDriftTrackerEngine.Report
