"""Recovery Test Engine — track disaster recovery test results, validate RPO/RTO compliance, m..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RecoveryTestEngine = engine(
    "RecoveryTestEngine",
    description="Track disaster recovery test results, validate RPO/RTO compliance, manage t...",
    enums={
        "recovery_type": EnumDef(
            "RecoveryType",
            {
                "FULL_RESTORE": "full_restore",
                "POINT_IN_TIME": "point_in_time",
                "PARTIAL": "partial",
                "TABLE_LEVEL": "table_level",
                "FILE_LEVEL": "file_level",
            },
        ),
        "test_outcome": EnumDef(
            "TestOutcome",
            {
                "SUCCESS": "success",
                "PARTIAL_SUCCESS": "partial_success",
                "FAILED": "failed",
                "TIMEOUT": "timeout",
                "DATA_LOSS": "data_loss",
            },
        ),
        "rpo_compliance": EnumDef(
            "RPOCompliance",
            {
                "WITHIN_TARGET": "within_target",
                "EXCEEDED": "exceeded",
                "FAR_EXCEEDED": "far_exceeded",
                "NOT_MEASURED": "not_measured",
                "NA": "na",
            },
        ),
    },
    record_fields=[
        FieldDef("service_name", str, ""),
        FieldDef("recovery_time_minutes", float, 0.0),
        FieldDef("data_loss_minutes", float, 0.0),
        FieldDef("data_recovered_pct", float, 100.0),
        FieldDef("target_rpo_minutes", float, 15.0),
        FieldDef("description", str, ""),
    ],
    key_field="test_name",
)

# Backward-compatible re-exports
RecoveryType = RecoveryTestEngine.RecoveryType
TestOutcome = RecoveryTestEngine.TestOutcome
RPOCompliance = RecoveryTestEngine.RPOCompliance
RecoveryTestRecord = RecoveryTestEngine.Record
RecoveryTestAnalysis = RecoveryTestEngine.Analysis
RecoveryTestReport = RecoveryTestEngine.Report
