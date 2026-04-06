"""DisasterRecoveryIntelligence DR readiness scoring, RTO/RPO tracking, failover testing, reco..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

DisasterRecoveryIntelligence = engine(
    "DisasterRecoveryIntelligence",
    module="operations",  # uses record_item
    description="DR readiness scoring with RTO/RPO tracking and failover testing validation.",
    enums={
        "dr_tier": EnumDef(
            "DRTier",
            {
                "TIER_1_CRITICAL": "tier_1_critical",
                "TIER_2_IMPORTANT": "tier_2_important",
                "TIER_3_STANDARD": "tier_3_standard",
                "TIER_4_LOW": "tier_4_low",
                "UNCLASSIFIED": "unclassified",
            },
        ),
        "recovery_strategy": EnumDef(
            "RecoveryStrategy",
            {
                "ACTIVE_ACTIVE": "active_active",
                "ACTIVE_PASSIVE": "active_passive",
                "PILOT_LIGHT": "pilot_light",
                "WARM_STANDBY": "warm_standby",
                "BACKUP_RESTORE": "backup_restore",
            },
        ),
        "failover_test_result": EnumDef(
            "FailoverTestResult",
            {
                "PASSED": "passed",
                "PARTIAL_PASS": "partial_pass",
                "FAILED": "failed",
                "NOT_TESTED": "not_tested",
                "EXPIRED": "expired",
            },
        ),
    },
    record_fields=[
        FieldDef("rto_target_minutes", float, 0.0),
        FieldDef("rto_actual_minutes", float, 0.0),
        FieldDef("rpo_target_minutes", float, 0.0),
        FieldDef("rpo_actual_minutes", float, 0.0),
        FieldDef("last_test_days_ago", int, 0),
        FieldDef("backup_verified", bool, False),
        FieldDef("runbook_current", bool, False),
    ],
    score_field="readiness_score",
)

# Backward-compatible re-exports
DRTier = DisasterRecoveryIntelligence.DRTier
RecoveryStrategy = DisasterRecoveryIntelligence.RecoveryStrategy
FailoverTestResult = DisasterRecoveryIntelligence.FailoverTestResult
DisasterRecoveryRecord = DisasterRecoveryIntelligence.Record
DisasterRecoveryAnalysis = DisasterRecoveryIntelligence.Analysis
DisasterRecoveryReport = DisasterRecoveryIntelligence.Report
