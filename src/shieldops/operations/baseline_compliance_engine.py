"""Baseline Compliance Engine — track config baseline compliance rates."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

BaselineComplianceEngine = engine(
    "BaselineComplianceEngine",
    description="Track config baseline compliance rates across infrastructure.",
    enums={
        "baseline_source": EnumDef(
            "BaselineSource",
            {
                "GOLDEN_IMAGE": "golden_image",
                "POLICY_FILE": "policy_file",
                "CIS_BENCHMARK": "cis_benchmark",
                "CUSTOM_RULE": "custom_rule",
                "INHERITED": "inherited",
            },
        ),
        "compliance_level": EnumDef(
            "ComplianceLevel",
            {
                "FULL": "full",
                "PARTIAL": "partial",
                "NON_COMPLIANT": "non_compliant",
                "EXEMPT": "exempt",
                "UNKNOWN": "unknown",
            },
        ),
        "validation_trigger": EnumDef(
            "ValidationTrigger",
            {
                "SCHEDULED": "scheduled",
                "ON_CHANGE": "on_change",
                "ON_DEPLOY": "on_deploy",
                "MANUAL": "manual",
                "CONTINUOUS": "continuous",
            },
        ),
    },
    record_fields=[
        FieldDef("service_id", str, ""),
        FieldDef("total_checks", int, 0),
        FieldDef("passed_checks", int, 0),
        FieldDef("failed_checks", int, 0),
        FieldDef("compliance_pct", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="resource_id",
)

# Backward-compatible re-exports
BaselineSource = BaselineComplianceEngine.BaselineSource
ComplianceLevel = BaselineComplianceEngine.ComplianceLevel
ValidationTrigger = BaselineComplianceEngine.ValidationTrigger
BaselineComplianceRecord = BaselineComplianceEngine.Record
BaselineComplianceAnalysis = BaselineComplianceEngine.Analysis
BaselineComplianceReport = BaselineComplianceEngine.Report
