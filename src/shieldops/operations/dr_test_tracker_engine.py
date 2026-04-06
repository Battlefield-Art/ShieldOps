"""DR Test Tracker Engine — track disaster recovery test outcomes."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DRTestTrackerEngine = engine(
    "DRTestTrackerEngine",
    description="Track disaster recovery test outcomes and RTO/RPO compliance.",
    enums={
        "test_type": EnumDef(
            "TestType",
            {
                "FAILOVER": "failover",
                "BACKUP_RESTORE": "backup_restore",
                "REGION_SWITCH": "region_switch",
                "DATA_RECOVERY": "data_recovery",
                "FULL_DR": "full_dr",
            },
        ),
        "test_outcome": EnumDef(
            "TestOutcome",
            {
                "SUCCESS": "success",
                "PARTIAL": "partial",
                "FAILED": "failed",
                "ABORTED": "aborted",
                "SKIPPED": "skipped",
            },
        ),
        "rto_compliance": EnumDef(
            "RTOCompliance",
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
        FieldDef("rto_target_seconds", float, 0.0),
        FieldDef("rto_actual_seconds", float, 0.0),
        FieldDef("rpo_target_seconds", float, 0.0),
        FieldDef("rpo_actual_seconds", float, 0.0),
        FieldDef("data_loss_bytes", int, 0),
        FieldDef("description", str, ""),
    ],
    key_field="service_id",
)

# Backward-compatible re-exports
TestType = DRTestTrackerEngine.TestType
TestOutcome = DRTestTrackerEngine.TestOutcome
RTOCompliance = DRTestTrackerEngine.RTOCompliance
DRTestTrackerRecord = DRTestTrackerEngine.Record
DRTestTrackerAnalysis = DRTestTrackerEngine.Analysis
DRTestTrackerReport = DRTestTrackerEngine.Report
