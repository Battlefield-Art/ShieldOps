"""Cloud Storage Scanner Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CSSStage(StrEnum):
    DISCOVER_BUCKETS = "discover_buckets"
    SCAN_PERMISSIONS = "scan_permissions"
    DETECT_SENSITIVE_DATA = "detect_sensitive_data"
    ASSESS_ENCRYPTION = "assess_encryption"
    REMEDIATE_ISSUES = "remediate_issues"
    REPORT = "report"


class StorageSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class StorageProvider(StrEnum):
    AWS_S3 = "aws_s3"
    GCP_GCS = "gcp_gcs"
    AZURE_BLOB = "azure_blob"
    MINIO = "minio"
    BACKBLAZE = "backblaze"


class StorageBucket(BaseModel):
    """A discovered cloud storage bucket."""

    id: str = ""
    name: str = ""
    provider: StorageProvider = StorageProvider.AWS_S3
    region: str = ""
    creation_date: str = ""
    public_access: bool = False
    versioning_enabled: bool = False
    logging_enabled: bool = False
    object_count: int = 0
    size_gb: float = 0.0
    tags: dict[str, str] = Field(default_factory=dict)


class PermissionFinding(BaseModel):
    """A permission misconfiguration finding."""

    id: str = ""
    bucket_name: str = ""
    severity: StorageSeverity = StorageSeverity.MEDIUM
    finding_type: str = ""
    description: str = ""
    principal: str = ""
    permission: str = ""
    is_public: bool = False
    recommendation: str = ""


class SensitiveDataFinding(BaseModel):
    """A sensitive data exposure finding."""

    id: str = ""
    bucket_name: str = ""
    severity: StorageSeverity = StorageSeverity.HIGH
    data_type: str = ""
    object_key: str = ""
    pattern_matched: str = ""
    sample_count: int = 0
    recommendation: str = ""


class EncryptionAssessment(BaseModel):
    """Encryption assessment for a bucket."""

    id: str = ""
    bucket_name: str = ""
    severity: StorageSeverity = StorageSeverity.MEDIUM
    encryption_enabled: bool = False
    encryption_type: str = ""
    kms_key_id: str = ""
    in_transit_enforced: bool = False
    recommendation: str = ""


class RemediationAction(BaseModel):
    """A remediation action taken or proposed."""

    id: str = ""
    finding_id: str = ""
    bucket_name: str = ""
    action_type: str = ""
    description: str = ""
    status: str = "proposed"
    auto_executable: bool = False
    rollback_available: bool = True
    risk: str = "low"


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudStorageScannerState(BaseModel):
    """Main state for the Cloud Storage Scanner agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CSSStage = CSSStage.DISCOVER_BUCKETS

    target_providers: list[str] = Field(
        default_factory=list,
    )
    buckets: list[StorageBucket] = Field(
        default_factory=list,
    )
    permission_findings: list[PermissionFinding] = Field(
        default_factory=list,
    )
    sensitive_data_findings: list[SensitiveDataFinding] = Field(
        default_factory=list,
    )
    encryption_assessments: list[EncryptionAssessment] = Field(
        default_factory=list,
    )
    remediation_actions: list[RemediationAction] = Field(
        default_factory=list,
    )

    report: str = ""
    total_buckets: int = 0
    total_findings: int = 0
    critical_findings: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
