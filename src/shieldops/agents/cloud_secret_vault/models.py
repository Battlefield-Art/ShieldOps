"""State models for the Cloud Secret Vault Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ----------------------------------------------------------


class VaultStage(StrEnum):
    """Workflow stages for cloud secret vault management."""

    DISCOVER_SECRETS = "discover_secrets"
    AUDIT_ROTATION = "audit_rotation"
    CHECK_EXPOSURE = "check_exposure"
    ASSESS_RISK = "assess_risk"
    REMEDIATE = "remediate"
    REPORT = "report"


class SecretRiskLevel(StrEnum):
    """Risk classification for discovered secrets."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    COMPLIANT = "compliant"


class SecretType(StrEnum):
    """Types of secrets managed."""

    API_KEY = "api_key"
    DATABASE_CREDENTIAL = "database_credential"
    SSH_KEY = "ssh_key"
    TLS_CERTIFICATE = "tls_certificate"
    OAUTH_TOKEN = "oauth_token"
    ENCRYPTION_KEY = "encryption_key"
    SERVICE_ACCOUNT = "service_account"


# -- Domain Models -----------------------------------------------------


class DiscoveredSecret(BaseModel):
    """A secret discovered during vault scanning."""

    secret_id: str = ""
    secret_type: SecretType = SecretType.API_KEY
    name: str = ""
    vault_provider: str = ""
    environment: str = ""
    owner: str = ""
    created_at: datetime | None = None
    last_rotated: datetime | None = None
    rotation_days: int = 0
    is_managed: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class RotationAudit(BaseModel):
    """Rotation audit result for a secret."""

    secret_id: str = ""
    rotation_policy_days: int = 90
    actual_rotation_days: int = 0
    is_compliant: bool = True
    is_overdue: bool = False
    days_overdue: int = 0
    last_rotated: datetime | None = None
    findings: list[str] = Field(default_factory=list)


class ExposureCheck(BaseModel):
    """Exposure check result for a secret."""

    secret_id: str = ""
    is_exposed: bool = False
    exposure_source: str = ""
    found_in_code: bool = False
    found_in_logs: bool = False
    found_in_config: bool = False
    public_leak: bool = False
    severity: str = "low"


class SecretRiskAssessment(BaseModel):
    """Risk assessment for a secret."""

    secret_id: str = ""
    risk_level: SecretRiskLevel = SecretRiskLevel.LOW
    risk_score: float = 0.0
    blast_radius: str = "low"
    business_impact: str = "low"
    reasoning: str = ""


class RemediationAction(BaseModel):
    """A remediation action for a secret risk."""

    action_id: str = ""
    secret_id: str = ""
    action_type: str = "rotate"
    priority: str = "medium"
    status: str = "pending"
    description: str = ""


# -- Reasoning + State -------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the vault workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CloudSecretVaultState(BaseModel):
    """Full state for the Cloud Secret Vault workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: VaultStage = VaultStage.DISCOVER_SECRETS
    scan_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Discovery
    discovered_secrets: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    unmanaged_count: int = 0

    # Rotation audit
    rotation_audits: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    overdue_count: int = 0

    # Exposure check
    exposure_checks: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    exposed_count: int = 0

    # Risk assessment
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    max_risk_score: float = 0.0

    # Remediation
    remediations: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
