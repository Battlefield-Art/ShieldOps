"""IaC Test Coverage Analyzer compute test coverage ratio, detect untested resources, rank mod..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

IacTestCoverageAnalyzer = engine(
    "IacTestCoverageAnalyzer",
    description="Compute test coverage ratio, detect untested resources, rank modules by tes...",
    enums={
        "test_type": EnumDef(
            "TestType",
            {
                "UNIT": "unit",
                "INTEGRATION": "integration",
                "CONTRACT": "contract",
                "E2E": "e2e",
            },
        ),
        "coverage_status": EnumDef(
            "CoverageStatus",
            {
                "COMPLETE": "complete",
                "PARTIAL": "partial",
                "MINIMAL": "minimal",
                "NONE": "none",
            },
        ),
        "test_framework": EnumDef(
            "TestFramework",
            {
                "TERRATEST": "terratest",
                "KITCHEN": "kitchen",
                "PYTEST": "pytest",
                "CUSTOM": "custom",
            },
        ),
    },
    record_fields=[
        FieldDef("module_name", str, ""),
        FieldDef("coverage_pct", float, 0.0),
        FieldDef("total_resources", int, 0),
        FieldDef("tested_resources", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="module_id",
)

# Backward-compatible re-exports
TestType = IacTestCoverageAnalyzer.TestType
CoverageStatus = IacTestCoverageAnalyzer.CoverageStatus
TestFramework = IacTestCoverageAnalyzer.TestFramework
TestCoverageRecord = IacTestCoverageAnalyzer.Record
TestCoverageAnalysis = IacTestCoverageAnalyzer.Analysis
TestCoverageReport = IacTestCoverageAnalyzer.Report
