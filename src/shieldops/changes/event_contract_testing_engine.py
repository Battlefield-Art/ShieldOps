"""Event Contract Testing Engine — validate contract compliance, detect contract drift, rank c..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

EventContractTestingEngine = engine(
    "EventContractTestingEngine",
    module="operations",  # uses record_item
    description="Validate contract compliance, detect drift, rank contracts by violation risk.",
    enums={
        "contract_status": EnumDef(
            "ContractStatus",
            {
                "COMPLIANT": "compliant",
                "DRIFTED": "drifted",
                "BROKEN": "broken",
                "UNTESTED": "untested",
            },
        ),
        "test_result": EnumDef(
            "TestResult",
            {
                "PASSED": "passed",
                "FAILED": "failed",
                "SKIPPED": "skipped",
                "ERROR": "error",
            },
        ),
        "drift_severity": EnumDef(
            "DriftSeverity",
            {
                "BREAKING": "breaking",
                "SIGNIFICANT": "significant",
                "MINOR": "minor",
                "COSMETIC": "cosmetic",
            },
        ),
    },
    record_fields=[
        FieldDef("violation_count", int, 0),
        FieldDef("coverage_pct", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="contract_id",
)

# Backward-compatible re-exports
ContractStatus = EventContractTestingEngine.ContractStatus
TestResult = EventContractTestingEngine.TestResult
DriftSeverity = EventContractTestingEngine.DriftSeverity
ContractTestRecord = EventContractTestingEngine.Record
ContractTestAnalysis = EventContractTestingEngine.Analysis
ContractTestReport = EventContractTestingEngine.Report
