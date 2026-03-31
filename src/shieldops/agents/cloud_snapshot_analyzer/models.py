"""State models for the Cloud Snapshot Analyzer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class CSAStage(StrEnum):
    """Stages in the cloud snapshot analysis lifecycle."""

    DISCOVER_SNAPSHOTS = "discover_snapshots"
    ANALYZE_CONFIG = "analyze_config"
    CHECK_ENCRYPTION = "check_encryption"
    DETECT_EXPOSURE = "detect_exposure"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class CloudProvider(StrEnum):
    """Supported cloud providers for snapshot analysis."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    MULTI_CLOUD = "multi_cloud"


class SnapshotType(StrEnum):
    """Types of cloud snapshots."""

    EBS_VOLUME = "ebs_volume"
    RDS_SNAPSHOT = "rds_snapshot"
    AMI = "ami"
    DISK_SNAPSHOT = "disk_snapshot"
    MANAGED_DISK = "managed_disk"
    BLOB_SNAPSHOT = "blob_snapshot"


# --- Domain models ---


class SnapshotInventory(BaseModel):
    """A discovered cloud snapshot."""

    snapshot_id: str = ""
    cloud_provider: CloudProvider = CloudProvider.AWS
    snapshot_type: SnapshotType = SnapshotType.EBS_VOLUME
    region: str = ""
    size_gb: float = 0.0
    created_at: datetime | None = None
    age_days: int = 0
    tags: dict[str, str] = Field(default_factory=dict)
    account_id: str = ""


class ConfigAnalysis(BaseModel):
    """Configuration analysis result for a snapshot."""

    snapshot_id: str = ""
    encrypted: bool = False
    encryption_type: str = ""
    public_access: bool = False
    cross_account_shared: bool = False
    lifecycle_policy: bool = False
    stale: bool = False


class EncryptionFinding(BaseModel):
    """Encryption audit finding for a snapshot."""

    snapshot_id: str = ""
    encrypted: bool = False
    kms_key_id: str = ""
    algorithm: str = ""
    compliant: bool = False
    recommendation: str = ""


class ExposureFinding(BaseModel):
    """Public exposure finding for a snapshot."""

    snapshot_id: str = ""
    exposure_type: str = ""
    severity: str = "medium"
    public_permissions: list[str] = Field(default_factory=list)
    shared_accounts: list[str] = Field(default_factory=list)
    remediation: str = ""


class RiskAssessment(BaseModel):
    """Risk assessment for a snapshot."""

    snapshot_id: str = ""
    risk_score: float = 0.0
    risk_level: str = "low"
    findings: list[str] = Field(default_factory=list)
    data_sensitivity: str = ""
    cost_monthly: float = 0.0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the analyzer workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CloudSnapshotAnalyzerState(BaseModel):
    """Full state for a cloud snapshot analyzer run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: CSAStage = CSAStage.DISCOVER_SNAPSHOTS

    # Inputs
    cloud_provider: CloudProvider = CloudProvider.AWS
    regions: list[str] = Field(default_factory=list)
    account_ids: list[str] = Field(default_factory=list)
    max_age_days: int = 90

    # Pipeline fields
    snapshots: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    config_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    encryption_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    exposure_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_snapshots: int = 0
    unencrypted_count: int = 0
    exposed_count: int = 0
    stale_count: int = 0
    high_risk_count: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
