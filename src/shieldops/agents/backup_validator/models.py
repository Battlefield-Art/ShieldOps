"""Backup Validator Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class BackupStage(StrEnum):
    INVENTORY_BACKUPS = "inventory_backups"
    VALIDATE_INTEGRITY = "validate_integrity"
    TEST_RECOVERY = "test_recovery"
    ASSESS_GAPS = "assess_gaps"
    REMEDIATE = "remediate"
    REPORT = "report"


class BackupType(StrEnum):
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"
    SNAPSHOT = "snapshot"
    LOG = "log"


class ValidationStatus(StrEnum):
    VALID = "valid"
    CORRUPTED = "corrupted"
    INCOMPLETE = "incomplete"
    MISSING = "missing"
    EXPIRED = "expired"


class BackupRecord(BaseModel):
    """A backup record in the inventory."""

    id: str = ""
    service: str = ""
    backup_type: BackupType = BackupType.FULL
    size_gb: float = 0.0
    created_at: datetime | None = None
    retention_days: int = 30
    encrypted: bool = True
    verified: bool = False
    storage_location: str = ""
    status: ValidationStatus = ValidationStatus.VALID


class IntegrityCheck(BaseModel):
    """Result of a backup integrity check."""

    backup_id: str = ""
    service: str = ""
    checksum_valid: bool = True
    size_match: bool = True
    encryption_valid: bool = True
    issues: list[str] = Field(default_factory=list)
    status: ValidationStatus = ValidationStatus.VALID


class RecoveryTest(BaseModel):
    """Result of a backup recovery test."""

    id: str = ""
    backup_id: str = ""
    recovery_time_min: float = 0.0
    data_loss_detected: bool = False
    success: bool = True
    details: str = ""
    rto_met: bool = True
    rpo_met: bool = True


class BackupGap(BaseModel):
    """An identified gap in backup coverage."""

    service: str = ""
    gap_type: str = ""
    severity: str = "medium"
    description: str = ""
    recommendation: str = ""


class BackupValidatorState(BaseModel):
    """Main state for the Backup Validator agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: BackupStage = BackupStage.INVENTORY_BACKUPS

    # Backup inventory
    backups: list[dict[str, Any]] = Field(default_factory=list)

    # Integrity checks
    integrity_checks: list[dict[str, Any]] = Field(default_factory=list)

    # Recovery tests
    recovery_tests: list[dict[str, Any]] = Field(default_factory=list)

    # Gaps
    gaps: list[dict[str, Any]] = Field(default_factory=list)

    # Remediations
    remediations: list[dict[str, Any]] = Field(default_factory=list)

    # Report
    summary: str = ""
    total_backups: int = 0
    valid_count: int = 0
    recovery_success_rate: float = 0.0

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
