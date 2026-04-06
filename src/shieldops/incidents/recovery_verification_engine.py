"""Recovery Verification Engine — verify recovery completeness, detect partial recoveries, ran..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

RecoveryVerificationEngine = engine(
    "RecoveryVerificationEngine",
    description="Verify recovery completeness, detect partial recoveries, rank recoveries by...",
    enums={
        "recovery_status": EnumDef(
            "RecoveryStatus",
            {
                "COMPLETE": "complete",
                "PARTIAL": "partial",
                "FAILED": "failed",
                "PENDING": "pending",
            },
        ),
        "verification_method": EnumDef(
            "VerificationMethod",
            {
                "SLI_COMPARISON": "sli_comparison",
                "HEALTH_CHECK": "health_check",
                "SYNTHETIC": "synthetic",
                "MANUAL": "manual",
            },
        ),
        "recovery_scope": EnumDef(
            "RecoveryScope",
            {
                "FULL": "full",
                "PARTIAL": "partial",
                "DEGRADED": "degraded",
            },
        ),
    },
    record_fields=[
        FieldDef("completeness_pct", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="incident_id",
)

# Backward-compatible re-exports
RecoveryStatus = RecoveryVerificationEngine.RecoveryStatus
VerificationMethod = RecoveryVerificationEngine.VerificationMethod
RecoveryScope = RecoveryVerificationEngine.RecoveryScope
RecoveryVerificationRecord = RecoveryVerificationEngine.Record
RecoveryVerificationAnalysis = RecoveryVerificationEngine.Analysis
RecoveryVerificationReport = RecoveryVerificationEngine.Report
