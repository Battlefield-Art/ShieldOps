"""Agent Code Generator — generate and validate agent code."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AgentCodeGenerator = engine(
    "AgentCodeGenerator",
    module="operations",  # uses record_item
    description="Generate, validate, and check agent code.",
    enums={
        "template": EnumDef(
            "TemplateType",
            {
                "INVESTIGATION": "investigation",
                "REMEDIATION": "remediation",
                "SECURITY": "security",
                "LEARNING": "learning",
                "CUSTOM": "custom",
            },
        ),
        "quality": EnumDef(
            "CodeQuality",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "ACCEPTABLE": "acceptable",
                "POOR": "poor",
                "FAILING": "failing",
            },
        ),
        "security": EnumDef(
            "SecurityCheck",
            {
                "PASSED": "passed",
                "WARNING": "warning",
                "FAILED": "failed",
                "SKIPPED": "skipped",
            },
        ),
    },
    key_field="agent_name",
)

# Backward-compatible re-exports
TemplateType = AgentCodeGenerator.TemplateType
CodeQuality = AgentCodeGenerator.CodeQuality
SecurityCheck = AgentCodeGenerator.SecurityCheck
CodeGenRecord = AgentCodeGenerator.Record
CodeGenAnalysis = AgentCodeGenerator.Analysis
CodeGenReport = AgentCodeGenerator.Report
