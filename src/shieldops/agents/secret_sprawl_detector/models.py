"""State models for the Secret Sprawl Detector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class SSDStage(StrEnum):
    """Stages in the secret sprawl detection lifecycle."""

    SCAN_REPOS = "scan_repos"
    SCAN_CONFIG = "scan_config"
    DETECT_SECRETS = "detect_secrets"
    CLASSIFY_RISK = "classify_risk"
    ALERT_OWNERS = "alert_owners"
    REPORT = "report"


class SecretType(StrEnum):
    """Types of secrets detected."""

    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"
    CONNECTION_STRING = "connection_string"


class DetectionMethod(StrEnum):
    """Methods used to detect secrets."""

    REGEX_PATTERN = "regex_pattern"
    ENTROPY_ANALYSIS = "entropy_analysis"
    GIT_HISTORY = "git_history"
    CONFIG_SCAN = "config_scan"
    SEMANTIC_ANALYSIS = "semantic_analysis"
    KNOWN_FORMAT = "known_format"


# --- Domain models ---


class RepoScanResult(BaseModel):
    """Result of scanning a repository for secrets."""

    repo_name: str = ""
    branch: str = "main"
    files_scanned: int = 0
    secrets_found: int = 0
    scan_duration_ms: int = 0
    last_commit: str = ""


class ConfigScanResult(BaseModel):
    """Result of scanning config files for secrets."""

    config_path: str = ""
    config_type: str = ""
    secrets_found: int = 0
    environments: list[str] = Field(
        default_factory=list,
    )


class SecretFinding(BaseModel):
    """A detected secret or credential."""

    finding_id: str = ""
    secret_type: SecretType = SecretType.API_KEY
    detection_method: DetectionMethod = DetectionMethod.REGEX_PATTERN
    file_path: str = ""
    line_number: int = 0
    snippet: str = ""
    repo_name: str = ""
    branch: str = "main"
    committed_by: str = ""
    committed_at: datetime | None = None
    entropy_score: float = 0.0
    verified: bool = False


class RiskClassification(BaseModel):
    """Risk classification for a secret finding."""

    finding_id: str = ""
    risk_level: str = "medium"
    exposure_scope: str = ""
    blast_radius: str = ""
    rotation_needed: bool = False
    age_days: int = 0
    recommendation: str = ""


class OwnerAlert(BaseModel):
    """Alert sent to a secret owner."""

    alert_id: str = ""
    finding_id: str = ""
    owner: str = ""
    channel: str = "email"
    sent_at: datetime | None = None
    acknowledged: bool = False


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the detector workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecretSprawlDetectorState(BaseModel):
    """Full state for a secret sprawl detector run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SSDStage = SSDStage.SCAN_REPOS

    # Inputs
    scan_name: str = ""
    target_repos: list[str] = Field(
        default_factory=list,
    )
    target_configs: list[str] = Field(
        default_factory=list,
    )
    scan_git_history: bool = True
    entropy_threshold: float = 4.5

    # Pipeline fields
    repo_scans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    config_scans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    alerts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_secrets: int = 0
    critical_secrets: int = 0
    repos_scanned: int = 0
    configs_scanned: int = 0
    alerts_sent: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
