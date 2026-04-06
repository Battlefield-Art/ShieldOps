"""InfrastructureDriftIntelligenceV2 Advanced drift detection, root cause classification, auto..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

InfrastructureDriftIntelligenceV2 = engine(
    "InfrastructureDriftIntelligenceV2",
    module="operations",  # uses record_item
    description="Advanced infrastructure drift detection. Root cause classification and auto...",
    enums={
        "category": EnumDef(
            "DriftCategory",
            {
                "CONFIGURATION": "configuration",
                "SECURITY_GROUP": "security_group",
                "IAM_POLICY": "iam_policy",
                "RESOURCE_TAG": "resource_tag",
                "NETWORK": "network",
                "STORAGE": "storage",
                "COMPUTE": "compute",
            },
        ),
        "root_cause": EnumDef(
            "DriftRootCause",
            {
                "MANUAL_CHANGE": "manual_change",
                "AUTO_SCALING": "auto_scaling",
                "PROVIDER_UPDATE": "provider_update",
                "FAILED_APPLY": "failed_apply",
                "EXTERNAL_TOOL": "external_tool",
                "UNKNOWN": "unknown",
            },
        ),
        "remediation_action": EnumDef(
            "RemediationAction",
            {
                "AUTO_REVERT": "auto_revert",
                "IMPORT_STATE": "import_state",
                "UPDATE_CODE": "update_code",
                "MANUAL_REVIEW": "manual_review",
                "IGNORE": "ignore",
            },
        ),
    },
    record_fields=[
        FieldDef("resource_type", str, ""),
        FieldDef("resource_id", str, ""),
        FieldDef("compliance_impact", bool, False),
        FieldDef("properties_drifted", int, 0),
        FieldDef("detected_by", str, ""),
        FieldDef("environment", str, ""),
    ],
    score_field="drift_score",
)

# Backward-compatible re-exports
DriftCategory = InfrastructureDriftIntelligenceV2.DriftCategory
DriftRootCause = InfrastructureDriftIntelligenceV2.DriftRootCause
RemediationAction = InfrastructureDriftIntelligenceV2.RemediationAction
InfrastructureDriftRecord = InfrastructureDriftIntelligenceV2.Record
InfrastructureDriftAnalysis = InfrastructureDriftIntelligenceV2.Analysis
InfrastructureDriftReport = InfrastructureDriftIntelligenceV2.Report
