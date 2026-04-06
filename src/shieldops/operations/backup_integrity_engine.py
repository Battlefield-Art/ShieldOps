"""Backup Integrity Engine — verify backup integrity, track verification status, manage storag..."""

from __future__ import annotations

from shieldops.engine import EnumDef, FieldDef, engine

BackupIntegrityEngine = engine(
    "BackupIntegrityEngine",
    description="Verify backup integrity, track verification status, manage storage tier lif...",
    enums={
        "backup_type": EnumDef(
            "BackupType",
            {
                "FULL": "full",
                "INCREMENTAL": "incremental",
                "DIFFERENTIAL": "differential",
                "SNAPSHOT": "snapshot",
                "CONTINUOUS": "continuous",
            },
        ),
        "integrity_status": EnumDef(
            "IntegrityStatus",
            {
                "VERIFIED": "verified",
                "CORRUPTED": "corrupted",
                "INCOMPLETE": "incomplete",
                "EXPIRED": "expired",
                "UNTESTED": "untested",
            },
        ),
        "storage_tier": EnumDef(
            "StorageTier",
            {
                "HOT": "hot",
                "WARM": "warm",
                "COLD": "cold",
                "ARCHIVE": "archive",
                "GLACIER": "glacier",
            },
        ),
    },
    record_fields=[
        FieldDef("service_name", str, ""),
        FieldDef("size_gb", float, 0.0),
        FieldDef("checksum", str, ""),
        FieldDef("retention_days", int, 30),
        FieldDef("last_verified_at", float, 0.0),
        FieldDef("description", str, ""),
    ],
    key_field="backup_id",
)

# Backward-compatible re-exports
BackupType = BackupIntegrityEngine.BackupType
IntegrityStatus = BackupIntegrityEngine.IntegrityStatus
StorageTier = BackupIntegrityEngine.StorageTier
BackupIntegrityRecord = BackupIntegrityEngine.Record
BackupIntegrityAnalysis = BackupIntegrityEngine.Analysis
BackupIntegrityReport = BackupIntegrityEngine.Report
