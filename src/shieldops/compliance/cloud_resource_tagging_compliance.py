"""Cloud Resource Tagging Compliance audit tag compliance, detect untagged resources, rank tea..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

CloudResourceTaggingCompliance = engine(
    "CloudResourceTaggingCompliance",
    description="Audit tag compliance, detect untagged resources, rank teams by tagging disc...",
    enums={
        "tag_status": EnumDef(
            "TagStatus",
            {
                "COMPLIANT": "compliant",
                "MISSING_REQUIRED": "missing_required",
                "INVALID_VALUE": "invalid_value",
                "EXCESS": "excess",
            },
        ),
        "tag_category": EnumDef(
            "TagCategory",
            {
                "COST_CENTER": "cost_center",
                "ENVIRONMENT": "environment",
                "OWNER": "owner",
                "PROJECT": "project",
            },
        ),
        "compliance_level": EnumDef(
            "ComplianceLevel",
            {
                "FULL": "full",
                "PARTIAL": "partial",
                "MINIMAL": "minimal",
                "NONE": "none",
            },
        ),
    },
    record_fields=[
        FieldDef("resource_name", str, ""),
        FieldDef("team_id", str, ""),
        FieldDef("missing_tags", int, 0),
        FieldDef("total_tags", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="resource_id",
)

# Backward-compatible re-exports
TagStatus = CloudResourceTaggingCompliance.TagStatus
TagCategory = CloudResourceTaggingCompliance.TagCategory
ComplianceLevel = CloudResourceTaggingCompliance.ComplianceLevel
TagComplianceRecord = CloudResourceTaggingCompliance.Record
TagComplianceAnalysis = CloudResourceTaggingCompliance.Analysis
TagComplianceReport = CloudResourceTaggingCompliance.Report
