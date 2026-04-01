"""State models for the Credential Hygiene Auditor Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CHAStage(StrEnum):
    """Stages of the credential hygiene audit lifecycle."""

    INVENTORY_CREDENTIALS = "inventory_credentials"
    ASSESS_HYGIENE = "assess_hygiene"
    DETECT_VIOLATIONS = "detect_violations"
    SCORE_RISK = "score_risk"
    RECOMMEND_FIXES = "recommend_fixes"
    REPORT = "report"


class CredentialType(StrEnum):
    """Types of credentials tracked."""

    PASSWORD = "password"
    API_KEY = "api_key"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"
    TOKEN = "token"
    SERVICE_ACCOUNT = "service_account"
    SECRET = "secret"
    OAUTH_CLIENT = "oauth_client"


class HygieneStatus(StrEnum):
    """Hygiene status classification for a credential."""

    COMPLIANT = "compliant"
    WARNING = "warning"
    NON_COMPLIANT = "non_compliant"
    EXPIRED = "expired"
    ORPHANED = "orphaned"
    OVERPRIVILEGED = "overprivileged"


class CredentialRecord(BaseModel):
    """A single credential inventory record."""

    record_id: str = ""
    credential_type: CredentialType = CredentialType.PASSWORD
    owner: str = ""
    system: str = ""
    created_at: datetime | None = None
    last_rotated: datetime | None = None
    expires_at: datetime | None = None
    age_days: int = 0
    rotation_policy_days: int = 90
    is_shared: bool = False
    scope: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class HygieneAssessment(BaseModel):
    """Hygiene assessment for a credential."""

    assessment_id: str = ""
    record_id: str = ""
    credential_type: CredentialType = CredentialType.PASSWORD
    status: HygieneStatus = HygieneStatus.COMPLIANT
    age_days: int = 0
    rotation_overdue: bool = False
    complexity_adequate: bool = True
    mfa_enabled: bool = False
    issues: list[str] = Field(default_factory=list)


class HygieneViolation(BaseModel):
    """A detected credential hygiene violation."""

    violation_id: str = ""
    record_id: str = ""
    violation_type: str = ""
    severity: str = "medium"
    description: str = ""
    policy_reference: str = ""
    remediation_hint: str = ""


class CredentialRiskScore(BaseModel):
    """Risk score for a credential or group."""

    score_id: str = ""
    scope: str = ""
    overall_score: float = Field(default=0.0, ge=0.0, le=1.0)
    violation_count: int = 0
    highest_severity: str = "low"
    contributing_factors: list[str] = Field(default_factory=list)
    blast_radius: str = "low"


class RemediationRecommendation(BaseModel):
    """Recommendation for fixing a credential hygiene issue."""

    recommendation_id: str = ""
    violation_id: str = ""
    priority: str = "medium"
    action: str = ""
    description: str = ""
    effort: str = "low"
    automated: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CredentialHygieneAuditorState(BaseModel):
    """Full LangGraph state for the Credential Hygiene Auditor."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: CHAStage = CHAStage.INVENTORY_CREDENTIALS
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    credentials: list[dict[str, Any]] = Field(default_factory=list)
    assessments: list[dict[str, Any]] = Field(default_factory=list)
    violations: list[dict[str, Any]] = Field(default_factory=list)
    risk_scores: list[dict[str, Any]] = Field(default_factory=list)
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Metrics
    credential_count: int = 0
    violation_count: int = 0
    compliant_count: int = 0

    # Metadata
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
