"""Security Workflow Generator — generate, validate, and measure workflows."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

SecurityWorkflowGenerator = engine(
    "SecurityWorkflowGenerator",
    description="Generate and validate security workflows.",
    enums={
        "complexity": EnumDef(
            "WorkflowComplexity",
            {
                "SIMPLE": "simple",
                "MODERATE": "moderate",
                "COMPLEX": "complex",
                "ADVANCED": "advanced",
                "EXPERT": "expert",
            },
        ),
        "code_quality": EnumDef(
            "CodeQuality",
            {
                "EXCELLENT": "excellent",
                "GOOD": "good",
                "ACCEPTABLE": "acceptable",
                "POOR": "poor",
                "FAILING": "failing",
            },
        ),
        "test_coverage": EnumDef(
            "TestCoverage",
            {
                "FULL": "full",
                "HIGH": "high",
                "MODERATE": "moderate",
                "LOW": "low",
                "NONE": "none",
            },
        ),
    },
    record_fields=[
        FieldDef("security_validated", bool, False),
        FieldDef("steps_count", int, 0),
    ],
    score_field="quality_score",
    key_field="workflow_name",
)

# Backward-compatible re-exports
WorkflowComplexity = SecurityWorkflowGenerator.WorkflowComplexity
CodeQuality = SecurityWorkflowGenerator.CodeQuality
TestCoverage = SecurityWorkflowGenerator.TestCoverage
WorkflowRecord = SecurityWorkflowGenerator.Record
WorkflowAnalysis = SecurityWorkflowGenerator.Analysis
WorkflowReport = SecurityWorkflowGenerator.Report
