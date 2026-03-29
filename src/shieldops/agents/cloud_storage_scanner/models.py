"""Cloud Storage Scanner Agent — Pydantic state and data models."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class StorageStage(StrEnum):
    DISCOVER_BUCKETS = "discover_buckets"
    SCAN_ACCESS = "scan_access"
    CHECK_ENCRYPTION = "check_encryption"
    DETECT_SENSITIVE_DATA = "detect_sensitive_data"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class StorageProvider(StrEnum):
    S3 = "s3"
    GCS = "gcs"
    AZURE_BLOB = "azure_blob"
    MINIO = "minio"


class StorageSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class StorageBucket(BaseModel):
    """A cloud storage bucket or container."""

    id: str = ""
    provider: StorageProvider = StorageProvider.S3
    bucket_name: str = ""
    region: str = ""
    creation_date: float = Field(default_factory=time.time)
    versioning_enabled: bool = False
    logging_enabled: bool = False
    encryption_type: str = "none"
    public_access_blocked: bool = True
    object_count: int = 0
    size_gb: float = 0.0
    tags: dict[str, str] = Field(default_factory=dict)


class AccessFinding(BaseModel):
    """An access control finding for a storage bucket."""

    id: str = ""
    bucket_id: str = ""
    finding_type: str = ""
    severity: StorageSeverity = StorageSeverity.MEDIUM
    description: str = ""
    public_readable: bool = False
    public_writable: bool = False
    overly_permissive_acl: bool = False
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)


class EncryptionFinding(BaseModel):
    """An encryption-related finding for a bucket."""

    id: str = ""
    bucket_id: str = ""
    finding_type: str = ""
    severity: StorageSeverity = StorageSeverity.MEDIUM
    encryption_type: str = "none"
    kms_key_id: str = ""
    description: str = ""
    compliant: bool = False


class SensitiveDataFinding(BaseModel):
    """Sensitive data detected in a storage bucket."""

    id: str = ""
    bucket_id: str = ""
    data_type: str = ""
    severity: StorageSeverity = StorageSeverity.HIGH
    file_pattern: str = ""
    estimated_count: int = 0
    description: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudStorageScannerState(BaseModel):
    """Main state for the Cloud Storage Scanner agent graph."""

    request_id: str = ""
    stage: StorageStage = StorageStage.DISCOVER_BUCKETS
    tenant_id: str = ""
    providers: list[str] = Field(default_factory=list)

    # Pipeline data
    buckets: list[dict[str, Any]] = Field(default_factory=list)
    access_findings: list[dict[str, Any]] = Field(default_factory=list)
    encryption_findings: list[dict[str, Any]] = Field(default_factory=list)
    sensitive_data_findings: list[dict[str, Any]] = Field(default_factory=list)

    # Risk assessment
    risk_score: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""

    # Timing
    session_start: float = Field(default_factory=time.time)
    session_duration_ms: float = 0.0

    # Error
    error: str = ""
