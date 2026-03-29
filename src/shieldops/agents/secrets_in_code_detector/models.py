"""Secrets in Code Detector Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DetectionStage(StrEnum):
    DISCOVER_REPOSITORIES = "discover_repositories"
    SCAN_PATTERNS = "scan_patterns"
    VERIFY_SECRETS = "verify_secrets"
    ASSESS_EXPOSURE = "assess_exposure"
    PRIORITIZE = "prioritize"
    REPORT = "report"


class SecretType(StrEnum):
    API_KEY = "api_key"
    PASSWORD = "password"  # noqa: S105
    TOKEN = "token"  # noqa: S105
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"
    CONNECTION_STRING = "connection_string"
    AWS_ACCESS_KEY = "aws_access_key"
    GCP_SERVICE_ACCOUNT = "gcp_service_account"
    AZURE_CLIENT_SECRET = "azure_client_secret"  # noqa: S105
    GENERIC_SECRET = "generic_secret"  # noqa: S105


class ExposureRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class RepositoryScan(BaseModel):
    """A repository scanned for secrets."""

    id: str = ""
    repo_name: str = ""
    repo_url: str = ""
    branch: str = "main"
    total_files: int = 0
    files_scanned: int = 0
    secrets_found: int = 0
    scan_duration_ms: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecretFinding(BaseModel):
    """A secret detected in source code."""

    id: str = ""
    secret_type: SecretType = SecretType.GENERIC_SECRET
    exposure_risk: ExposureRisk = ExposureRisk.HIGH
    file_path: str = ""
    line_number: int = 0
    column: int = 0
    snippet_masked: str = ""
    rule_id: str = ""
    is_active: bool = False
    is_in_history: bool = False
    commit_sha: str = ""
    author: str = ""
    committed_at: str = ""
    remediation: str = ""
    verified: bool = False
    entropy_score: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecretsInCodeDetectorState(BaseModel):
    """Full state for the Secrets in Code Detector agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: DetectionStage = DetectionStage.DISCOVER_REPOSITORIES
    scan_targets: list[str] = Field(default_factory=list)
    repositories: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_repos: int = 0
    raw_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    verified_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    exposure_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    prioritized: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_findings: int = 0
    critical_count: int = 0
    active_secrets: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
