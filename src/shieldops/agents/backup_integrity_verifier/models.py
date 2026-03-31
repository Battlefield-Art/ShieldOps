"""State models for the Backup Integrity Verifier Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class BIVStage(StrEnum):
    """Stages in the backup integrity verification lifecycle."""

    DISCOVER_BACKUPS = "discover_backups"
    VERIFY_INTEGRITY = "verify_integrity"
    CHECK_ENCRYPTION = "check_encryption"
    TEST_RESTORE = "test_restore"
    ASSESS_COVERAGE = "assess_coverage"
    REPORT = "report"


class BackupType(StrEnum):
    """Type of backup being verified."""

    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"
    SNAPSHOT = "snapshot"
    CONTINUOUS = "continuous"
    ARCHIVE = "archive"


class VerificationStatus(StrEnum):
    """Status of a backup verification check."""

    PASSED = "passed"
    FAILED = "failed"
    DEGRADED = "degraded"
    SKIPPED = "skipped"
    PENDING = "pending"
    EXPIRED = "expired"


# --- Domain models ---


class BackupRecord(BaseModel):
    """A discovered backup record."""

    backup_id: str = ""
    backup_type: BackupType = BackupType.FULL
    source_system: str = ""
    storage_location: str = ""
    size_bytes: int = 0
    created_at: datetime | None = None
    retention_days: int = 30
    encrypted: bool = False


class IntegrityCheck(BaseModel):
    """Result of a backup integrity verification."""

    check_id: str = ""
    backup_id: str = ""
    hash_algorithm: str = "sha256"
    expected_hash: str = ""
    actual_hash: str = ""
    status: VerificationStatus = VerificationStatus.PENDING
    checked_at: datetime | None = None


class EncryptionCheck(BaseModel):
    """Result of backup encryption validation."""

    backup_id: str = ""
    encrypted: bool = False
    algorithm: str = ""
    key_rotation_compliant: bool = False
    at_rest_encrypted: bool = False
    in_transit_encrypted: bool = False


class RestoreTest(BaseModel):
    """Result of a backup restore test."""

    test_id: str = ""
    backup_id: str = ""
    restore_target: str = ""
    success: bool = False
    duration_seconds: int = 0
    data_integrity_verified: bool = False
    rpo_met: bool = False
    rto_met: bool = False


class CoverageAssessment(BaseModel):
    """Assessment of backup coverage gaps."""

    total_systems: int = 0
    covered_systems: int = 0
    coverage_pct: float = 0.0
    gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    compliance_status: str = "unknown"


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the orchestrator workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class BackupIntegrityVerifierState(BaseModel):
    """Full state for a backup integrity verifier run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: BIVStage = BIVStage.DISCOVER_BACKUPS

    # Inputs
    target_systems: list[str] = Field(default_factory=list)
    storage_locations: list[str] = Field(
        default_factory=list,
    )
    scope: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    backups: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    integrity_checks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    encryption_checks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    restore_tests: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    coverage: dict[str, Any] = Field(
        default_factory=dict,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_backups: int = 0
    passed_integrity: int = 0
    failed_integrity: int = 0
    encryption_compliant: int = 0
    restore_success_rate: float = 0.0
    coverage_pct: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
