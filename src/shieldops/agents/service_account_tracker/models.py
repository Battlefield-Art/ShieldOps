"""Service Account Tracker — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class TrackerStage(StrEnum):
    DISCOVER = "discover"
    ANALYZE_USAGE = "analyze_usage"
    DETECT_ANOMALIES = "detect_anomalies"
    CLASSIFY_RISK = "classify_risk"
    REMEDIATE = "remediate"
    REPORT = "report"


class AccountStatus(StrEnum):
    ACTIVE = "active"
    DORMANT = "dormant"
    ORPHANED = "orphaned"
    SHARED = "shared"
    COMPROMISED = "compromised"
    COMPLIANT = "compliant"


class CloudSource(StrEnum):
    AWS_IAM = "aws_iam"
    GCP_IAM = "gcp_iam"
    AZURE_AD = "azure_ad"
    KUBERNETES_SA = "kubernetes_sa"
    GITHUB_APP = "github_app"
    VAULT = "vault"


class ServiceAccount(BaseModel):
    """A single service account discovered across any cloud provider."""

    id: str = ""
    name: str = ""
    cloud_source: CloudSource = CloudSource.AWS_IAM
    owner: str = ""
    created_at: float = 0.0
    last_used: float = 0.0
    days_inactive: int = 0
    permissions: list[str] = Field(default_factory=list)
    mfa_enabled: bool = False
    key_count: int = 0
    status: AccountStatus = AccountStatus.ACTIVE
    risk_score: float = 0.0


class UsageAnomaly(BaseModel):
    """An anomaly detected in service account usage patterns."""

    id: str = ""
    account_id: str = ""
    anomaly_type: str = ""
    description: str = ""
    severity: str = "low"
    confidence: float = 0.0
    source_ip: str = ""
    timestamp: float = 0.0


class SharingDetection(BaseModel):
    """Evidence that a service account credential is shared across entities."""

    id: str = ""
    account_id: str = ""
    shared_with: list[str] = Field(default_factory=list)
    detection_method: str = ""
    risk_level: str = "medium"


class RemediationAction(BaseModel):
    """A remediation action applied (or proposed) for a service account."""

    id: str = ""
    account_id: str = ""
    action: str = ""
    description: str = ""
    applied: bool = False
    success: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ServiceAccountTrackerState(BaseModel):
    """Main state for the Service Account Tracker graph."""

    # Input
    request_id: str = ""
    stage: TrackerStage = TrackerStage.DISCOVER
    tenant_id: str = ""

    # Discovery & analysis
    service_accounts: list[dict[str, Any]] = Field(default_factory=list)
    usage_anomalies: list[dict[str, Any]] = Field(default_factory=list)
    sharing_detections: list[dict[str, Any]] = Field(default_factory=list)
    remediation_actions: list[dict[str, Any]] = Field(default_factory=list)

    # Metrics
    orphaned_count: int = 0
    shared_count: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
