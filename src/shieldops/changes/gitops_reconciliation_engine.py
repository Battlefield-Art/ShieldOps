"""GitOpsReconciliationEngine Git-to-cluster state reconciliation, drift detection, auto-sync..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

GitOpsReconciliationEngine = engine(
    "GitOpsReconciliationEngine",
    module="operations",  # uses record_item
    description="Git-to-cluster state reconciliation with drift detection and auto-sync.",
    enums={
        "status": EnumDef(
            "ReconciliationStatus",
            {
                "SYNCED": "synced",
                "DRIFTED": "drifted",
                "SYNCING": "syncing",
                "CONFLICT": "conflict",
                "FAILED": "failed",
            },
        ),
        "drift_severity": EnumDef(
            "DriftSeverity",
            {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "INFO": "info",
            },
        ),
        "sync_strategy": EnumDef(
            "SyncStrategy",
            {
                "AUTO_SYNC": "auto_sync",
                "MANUAL_APPROVAL": "manual_approval",
                "DRY_RUN": "dry_run",
                "FORCE_SYNC": "force_sync",
                "ROLLBACK": "rollback",
            },
        ),
    },
    record_fields=[
        FieldDef("cluster", str, ""),
        FieldDef("namespace", str, ""),
        FieldDef("repo_url", str, ""),
        FieldDef("branch", str, "main"),
        FieldDef("desired_hash", str, ""),
        FieldDef("actual_hash", str, ""),
        FieldDef("drift_resources", int, 0),
        FieldDef("sync_duration_seconds", float, 0.0),
    ],
)

# Backward-compatible re-exports
ReconciliationStatus = GitOpsReconciliationEngine.ReconciliationStatus
DriftSeverity = GitOpsReconciliationEngine.DriftSeverity
SyncStrategy = GitOpsReconciliationEngine.SyncStrategy
ReconciliationRecord = GitOpsReconciliationEngine.Record
ReconciliationAnalysis = GitOpsReconciliationEngine.Analysis
ReconciliationReport = GitOpsReconciliationEngine.Report
