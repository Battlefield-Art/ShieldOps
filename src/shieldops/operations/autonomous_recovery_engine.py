"""AutonomousRecoveryEngine — autonomous recovery engine."""

from __future__ import annotations

from shieldops.engine import EnumDef, engine

AutonomousRecoveryEngine = engine(
    "AutonomousRecoveryEngine",
    module="operations",  # uses record_item
    description="Autonomous Recovery Engine.",
    enums={
        "recovery_type": EnumDef(
            "RecoveryType",
            {
                "FAILOVER": "failover",
                "ROLLBACK": "rollback",
                "RESTORE": "restore",
                "REBUILD": "rebuild",
                "SCALE": "scale",
            },
        ),
        "recovery_target": EnumDef(
            "RecoveryTarget",
            {
                "SERVICE": "service",
                "DATABASE": "database",
                "INFRASTRUCTURE": "infrastructure",
                "NETWORK": "network",
                "APPLICATION": "application",
            },
        ),
        "recovery_status": EnumDef(
            "RecoveryStatus",
            {
                "COMPLETED": "completed",
                "IN_PROGRESS": "in_progress",
                "FAILED": "failed",
                "PARTIAL": "partial",
                "PENDING": "pending",
            },
        ),
    },
)

# Backward-compatible re-exports
RecoveryType = AutonomousRecoveryEngine.RecoveryType
RecoveryTarget = AutonomousRecoveryEngine.RecoveryTarget
RecoveryStatus = AutonomousRecoveryEngine.RecoveryStatus
AutonomousRecoveryEngineRecord = AutonomousRecoveryEngine.Record
AutonomousRecoveryEngineAnalysis = AutonomousRecoveryEngine.Analysis
AutonomousRecoveryEngineReport = AutonomousRecoveryEngine.Report
