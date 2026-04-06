"""IacValidationEngine Terraform/OpenTofu plan validation, policy compliance checking, cost es..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IacValidationEngine = engine(
    "IacValidationEngine",
    module="operations",  # uses record_item
    description="Terraform/OpenTofu plan validation with policy compliance and cost estimation.",
    enums={
        "tool_type": EnumDef(
            "IacToolType",
            {
                "TERRAFORM": "terraform",
                "OPENTOFU": "opentofu",
                "PULUMI": "pulumi",
                "CLOUDFORMATION": "cloudformation",
                "CROSSPLANE": "crossplane",
            },
        ),
        "validation_result": EnumDef(
            "ValidationResult",
            {
                "PASSED": "passed",
                "FAILED": "failed",
                "WARNING": "warning",
                "SKIPPED": "skipped",
                "ERROR": "error",
            },
        ),
        "blast_radius": EnumDef(
            "BlastRadiusLevel",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "MINIMAL": "minimal",
            },
        ),
    },
    record_fields=[
        FieldDef("resources_added", int, 0),
        FieldDef("resources_changed", int, 0),
        FieldDef("resources_destroyed", int, 0),
        FieldDef("estimated_cost_delta", float, 0.0),
        FieldDef("policy_violations", int, 0),
        FieldDef("plan_file", str, ""),
        FieldDef("workspace", str, ""),
    ],
)

# Backward-compatible re-exports
IacToolType = IacValidationEngine.IacToolType
ValidationResult = IacValidationEngine.ValidationResult
BlastRadiusLevel = IacValidationEngine.BlastRadiusLevel
IacValidationRecord = IacValidationEngine.Record
IacValidationAnalysis = IacValidationEngine.Analysis
IacValidationReport = IacValidationEngine.Report
