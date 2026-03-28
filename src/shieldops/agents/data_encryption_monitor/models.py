"""Data Encryption Monitor Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class EncryptionStage(StrEnum):
    SCAN_ASSETS = "scan_assets"
    ASSESS_ENCRYPTION = "assess_encryption"
    CHECK_KEY_ROTATION = "check_key_rotation"
    CHECK_CERTIFICATES = "check_certificates"
    IDENTIFY_GAPS = "identify_gaps"
    REPORT = "report"


class EncryptionType(StrEnum):
    AT_REST = "at_rest"
    IN_TRANSIT = "in_transit"
    END_TO_END = "end_to_end"
    FIELD_LEVEL = "field_level"
    NONE = "none"


class CertificateStatus(StrEnum):
    VALID = "valid"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SELF_SIGNED = "self_signed"
    UNKNOWN = "unknown"


class EncryptionAsset(BaseModel):
    """A data store or service with encryption posture."""

    id: str = ""
    name: str = ""
    asset_type: str = ""  # s3 / rds / ebs / api / service
    cloud_provider: str = ""  # aws / gcp / azure / on_prem
    region: str = ""
    encryption_type: EncryptionType = EncryptionType.NONE
    algorithm: str = ""  # AES-256 / TLS1.3 / ChaCha20, etc.
    key_id: str = ""
    is_encrypted: bool = False
    owner: str = ""
    last_assessed: float = 0.0
    compliance_tags: list[str] = Field(default_factory=list)


class KeyRotationStatus(BaseModel):
    """Key rotation schedule and health."""

    key_id: str = ""
    key_alias: str = ""
    provider: str = ""  # aws_kms / gcp_kms / azure_keyvault / vault
    algorithm: str = ""
    created_at: float = 0.0
    last_rotated: float = 0.0
    rotation_interval_days: int = 0
    next_rotation: float = 0.0
    is_overdue: bool = False
    auto_rotation_enabled: bool = False
    days_until_rotation: int = 0
    usage_count: int = 0


class CertificateHealth(BaseModel):
    """TLS/SSL certificate health record."""

    id: str = ""
    domain: str = ""
    issuer: str = ""
    serial_number: str = ""
    status: CertificateStatus = CertificateStatus.UNKNOWN
    not_before: float = 0.0
    not_after: float = 0.0
    days_until_expiry: int = 0
    key_size: int = 0
    signature_algorithm: str = ""
    san_domains: list[str] = Field(default_factory=list)
    is_wildcard: bool = False
    auto_renew: bool = False


class EncryptionGap(BaseModel):
    """An identified encryption gap or weakness."""

    id: str = ""
    asset_id: str = ""
    gap_type: str = ""  # unencrypted / weak_algo / expired_cert / overdue_rotation
    severity: str = "medium"  # low / medium / high / critical
    description: str = ""
    recommendation: str = ""
    compliance_impact: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class DataEncryptionMonitorState(BaseModel):
    """Main state for the Data Encryption Monitor graph."""

    # Input
    request_id: str = ""
    stage: EncryptionStage = EncryptionStage.SCAN_ASSETS
    tenant_id: str = ""

    # Data
    assets_scanned: list[dict[str, Any]] = Field(default_factory=list)
    encryption_assessments: list[dict[str, Any]] = Field(default_factory=list)
    key_rotation_statuses: list[dict[str, Any]] = Field(default_factory=list)
    certificate_health: list[dict[str, Any]] = Field(default_factory=list)
    encryption_gaps: list[dict[str, Any]] = Field(default_factory=list)

    # Metrics
    encryption_coverage_pct: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
