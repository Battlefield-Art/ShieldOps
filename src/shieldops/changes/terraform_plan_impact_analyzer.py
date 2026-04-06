"""Terraform Plan Impact Analyzer analyze terraform plan impacts, detect destructive changes,..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

TerraformPlanImpactAnalyzer = engine(
    "TerraformPlanImpactAnalyzer",
    module="operations",  # uses record_item
    description="Analyze terraform plan impacts, detect destructive changes, rank plans by r...",
    enums={
        "change_action": EnumDef(
            "ChangeAction",
            {
                "CREATE": "create",
                "UPDATE": "update",
                "DELETE": "delete",
                "REPLACE": "replace",
            },
        ),
        "impact_level": EnumDef(
            "ImpactLevel",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
            },
        ),
        "resource_category": EnumDef(
            "ResourceCategory",
            {
                "COMPUTE": "compute",
                "STORAGE": "storage",
                "NETWORK": "network",
                "SECURITY": "security",
            },
        ),
    },
    record_fields=[
        FieldDef("resource_name", str, ""),
        FieldDef("affected_resources", int, 0),
        FieldDef("description", str, ""),
    ],
    score_field="risk_score",
    key_field="plan_id",
)

# Backward-compatible re-exports
ChangeAction = TerraformPlanImpactAnalyzer.ChangeAction
ImpactLevel = TerraformPlanImpactAnalyzer.ImpactLevel
ResourceCategory = TerraformPlanImpactAnalyzer.ResourceCategory
TerraformPlanRecord = TerraformPlanImpactAnalyzer.Record
TerraformPlanAnalysis = TerraformPlanImpactAnalyzer.Analysis
TerraformPlanReport = TerraformPlanImpactAnalyzer.Report
