"""Secrets Scanner Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ScannerStage(StrEnum):
    SCAN_SOURCES = "scan_sources"
    DETECT_SECRETS = "detect_secrets"
    CLASSIFY_SEVERITY = "classify_severity"
    VERIFY_EXPOSURE = "verify_exposure"
    REMEDIATE = "remediate"
    REPORT = "report"


class SecretType(StrEnum):
    API_KEY = "api_key"
    AWS_ACCESS_KEY = "aws_access_key"
    GCP_SERVICE_KEY = "gcp_service_key"
    AZURE_SECRET = "azure_secret"  # noqa: S105
    DATABASE_URL = "database_url"
    PRIVATE_KEY = "private_key"
    OAUTH_TOKEN = "oauth_token"  # noqa: S105
    JWT_SECRET = "jwt_secret"  # noqa: S105
    WEBHOOK_SECRET = "webhook_secret"  # noqa: S105
    GENERIC_PASSWORD = "generic_password"  # noqa: S105


class SourceType(StrEnum):
    GIT_REPO = "git_repo"
    CONFIG_FILE = "config_file"
    CONTAINER_IMAGE = "container_image"
    LOG_FILE = "log_file"
    ENV_VARIABLE = "env_variable"
    CI_CD_PIPELINE = "ci_cd_pipeline"
    SLACK_MESSAGE = "slack_message"


class ExposureLevel(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


class SecretFinding(BaseModel):
    """A single detected secret in a scanned source."""

    id: str = ""
    secret_type: SecretType = SecretType.GENERIC_PASSWORD
    source_type: SourceType = SourceType.GIT_REPO
    source_path: str = ""
    line_number: int = 0
    masked_value: str = ""
    exposure_level: ExposureLevel = ExposureLevel.UNKNOWN
    confidence: float = 0.0
    is_active: bool = False
    created_at: float = 0.0
    repository: str = ""
    branch: str = ""


class SeverityAssessment(BaseModel):
    """Severity assessment for a detected secret finding."""

    id: str = ""
    finding_id: str = ""
    severity: str = "medium"
    blast_radius: str = ""
    affected_services: list[str] = Field(default_factory=list)
    data_at_risk: str = ""
    is_rotated: bool = False


class RemediationAction(BaseModel):
    """A remediation action taken for a leaked secret."""

    id: str = ""
    finding_id: str = ""
    action: str = ""
    target: str = ""
    description: str = ""
    auto_executed: bool = False
    success: bool = False
    rotated_credential_id: str = ""


class ReasoningStep(BaseModel):
    """A single reasoning step in the agent chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecretsScannerState(BaseModel):
    """Full state for the Secrets Scanner agent workflow."""

    request_id: str = ""
    stage: ScannerStage = ScannerStage.SCAN_SOURCES
    tenant_id: str = ""
    scan_targets: list[str] = Field(default_factory=list)
    secret_findings: list[SecretFinding] = Field(default_factory=list)
    severity_assessments: list[SeverityAssessment] = Field(default_factory=list)
    remediation_actions: list[RemediationAction] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
