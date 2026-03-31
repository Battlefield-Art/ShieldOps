"""Credential Exposure Scanner Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CESStage(StrEnum):
    SCAN_SOURCES = "scan_sources"
    DETECT_CREDENTIALS = "detect_credentials"
    CLASSIFY_TYPE = "classify_type"
    ASSESS_EXPOSURE = "assess_exposure"
    TRIGGER_ROTATION = "trigger_rotation"
    REPORT = "report"


class CredentialType(StrEnum):
    API_KEY = "api_key"
    ACCESS_TOKEN = "access_token"
    PASSWORD = "password"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"
    CONNECTION_STRING = "connection_string"


class ExposureSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    FALSE_POSITIVE = "false_positive"


class ScanSource(BaseModel):
    """A source scanned for credential exposure."""

    id: str = ""
    source_type: str = ""
    source_url: str = ""
    scan_time: str = ""
    items_scanned: int = 0
    credentials_found: int = 0
    status: str = "completed"


class DetectedCredential(BaseModel):
    """A credential detected in a scan source."""

    id: str = ""
    source_id: str = ""
    raw_snippet: str = ""
    file_path: str = ""
    line_number: int = 0
    commit_hash: str = ""
    author: str = ""
    detected_at: str = ""
    entropy_score: float = 0.0


class CredentialClassification(BaseModel):
    """Classification result for a detected credential."""

    id: str = ""
    credential_id: str = ""
    credential_type: CredentialType = CredentialType.API_KEY
    provider: str = ""
    service: str = ""
    is_active: bool = False
    pattern_match: str = ""
    confidence: float = 0.0


class ExposureAssessment(BaseModel):
    """Exposure severity assessment for a credential."""

    id: str = ""
    credential_id: str = ""
    severity: ExposureSeverity = ExposureSeverity.MEDIUM
    exposure_scope: str = ""
    time_exposed_hours: int = 0
    accessible_resources: list[str] = Field(default_factory=list)
    lateral_movement_risk: bool = False
    data_at_risk: str = ""


class RotationAction(BaseModel):
    """Credential rotation action triggered."""

    id: str = ""
    credential_id: str = ""
    action: str = ""
    status: str = ""
    new_credential_generated: bool = False
    old_credential_revoked: bool = False
    services_updated: list[str] = Field(default_factory=list)
    rollback_available: bool = True


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CredentialExposureScannerState(BaseModel):
    """Main state for the Credential Exposure Scanner agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: CESStage = CESStage.SCAN_SOURCES

    scan_sources: list[ScanSource] = Field(
        default_factory=list,
    )
    detected_credentials: list[DetectedCredential] = Field(
        default_factory=list,
    )
    classifications: list[CredentialClassification] = Field(
        default_factory=list,
    )
    exposure_assessments: list[ExposureAssessment] = Field(
        default_factory=list,
    )
    rotation_actions: list[RotationAction] = Field(
        default_factory=list,
    )

    report: str = ""
    total_sources_scanned: int = 0
    credentials_detected: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
