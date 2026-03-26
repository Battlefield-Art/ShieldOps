"""State models for the Cyber Recovery Agent LangGraph workflow."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RecoveryStage(StrEnum):
    """Stages of the cyber recovery workflow."""

    ASSESS_DAMAGE = "assess_damage"
    SELECT_RECOVERY_POINTS = "select_recovery_points"
    VALIDATE_CLEAN_ROOM = "validate_clean_room"
    EXECUTE_RECOVERY = "execute_recovery"
    VERIFY_INTEGRITY = "verify_integrity"
    REPORT = "report"


class RecoveryType(StrEnum):
    """Types of cyber recovery operations."""

    FULL_RESTORE = "full_restore"
    GRANULAR_RESTORE = "granular_restore"
    CLEAN_ROOM = "clean_room"
    PARALLEL_RECOVERY = "parallel_recovery"
    FAILOVER = "failover"


class ValidationStatus(StrEnum):
    """Status of clean room validation on a snapshot."""

    CLEAN = "clean"
    INFECTED = "infected"
    SUSPICIOUS = "suspicious"
    UNTESTED = "untested"


class DamageAssessment(BaseModel):
    """Assessment of damage from a cyber incident."""

    id: str = ""
    affected_systems: list[str] = Field(default_factory=list)
    encrypted_assets: list[str] = Field(default_factory=list)
    corrupted_assets: list[str] = Field(default_factory=list)
    data_exfiltrated: bool = False
    attack_vector: str = ""
    malware_family: str = ""
    severity: str = "high"
    blast_radius: int = 0
    timestamp: float = 0.0


class RecoveryPoint(BaseModel):
    """A candidate recovery point (snapshot/backup)."""

    id: str = ""
    source_system: str = ""
    snapshot_time: float = 0.0
    cloud_provider: str = ""
    storage_location: str = ""
    size_gb: float = 0.0
    retention_days: int = 0
    validation_status: ValidationStatus = ValidationStatus.UNTESTED
    is_immutable: bool = False
    encryption_intact: bool = True


class CleanRoomValidation(BaseModel):
    """Result of scanning a recovery point in an isolated clean room."""

    id: str = ""
    recovery_point_id: str = ""
    scan_engine: str = ""
    malware_detected: bool = False
    persistence_mechanisms: list[str] = Field(default_factory=list)
    ioc_matches: list[str] = Field(default_factory=list)
    validation_status: ValidationStatus = ValidationStatus.UNTESTED
    scan_duration_sec: float = 0.0
    confidence: float = 0.0


class RecoveryExecution(BaseModel):
    """Result of executing a recovery operation."""

    id: str = ""
    recovery_point_id: str = ""
    recovery_type: RecoveryType = RecoveryType.FULL_RESTORE
    target_system: str = ""
    cloud_provider: str = ""
    started_at: float = 0.0
    completed_at: float = 0.0
    success: bool = False
    data_restored_gb: float = 0.0
    rto_actual_sec: float = 0.0
    error_message: str = ""


class IntegrityVerification(BaseModel):
    """Post-recovery integrity verification result."""

    id: str = ""
    recovery_id: str = ""
    checksum_valid: bool = False
    services_healthy: bool = False
    data_consistency: bool = False
    no_malware_reinfection: bool = False
    application_functional: bool = False
    verification_score: float = 0.0


class ReasoningStep(BaseModel):
    """Audit trail entry for the cyber recovery workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CyberRecoveryState(BaseModel):
    """Full state for a cyber recovery workflow run."""

    # Input
    tenant_id: str = ""
    incident_id: str = ""
    recovery_type: RecoveryType = RecoveryType.FULL_RESTORE

    # Damage assessment
    damage: DamageAssessment = Field(default_factory=DamageAssessment)
    damage_scope: dict[str, Any] = Field(default_factory=dict)

    # Recovery point selection
    recovery_points: list[RecoveryPoint] = Field(default_factory=list)
    selected_point_id: str = ""

    # Clean room validation
    validations: list[CleanRoomValidation] = Field(default_factory=list)
    has_clean_point: bool = False

    # Recovery execution
    recoveries_executed: list[RecoveryExecution] = Field(default_factory=list)
    recovery_success: bool = False

    # Integrity verification
    integrity_verified: bool = False
    integrity_results: list[IntegrityVerification] = Field(default_factory=list)

    # RTO/RPO tracking
    rto_seconds: float = 0.0
    rpo_seconds: float = 0.0
    rto_target_seconds: float = 3600.0
    rpo_target_seconds: float = 900.0

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str | None = None
