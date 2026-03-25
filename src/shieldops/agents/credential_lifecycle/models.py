"""Credential Lifecycle Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class LifecycleStage(StrEnum):
    DISCOVER = "discover"
    ASSESS_POSTURE = "assess_posture"
    ISSUE_JIT = "issue_jit"
    ENFORCE_ROTATION = "enforce_rotation"
    REVOKE_STALE = "revoke_stale"
    REPORT = "report"


class CredentialType(StrEnum):
    API_KEY = "api_key"
    OAUTH_TOKEN = "oauth_token"  # noqa: S105
    SERVICE_ACCOUNT = "service_account"
    JWT_TOKEN = "jwt_token"  # noqa: S105
    CERTIFICATE = "certificate"
    SSH_KEY = "ssh_key"


class PostureRating(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    CRITICAL = "critical"


# --- Supporting models ---


class CredentialRecord(BaseModel):
    """A discovered credential in the environment."""

    id: str = ""
    name: str = ""
    credential_type: CredentialType = CredentialType.API_KEY
    owner: str = ""
    created_at: str = ""
    last_used: str = ""
    expires_at: str = ""
    scope: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    is_stale: bool = False
    auto_rotatable: bool = True


class PostureAssessment(BaseModel):
    """Posture assessment result for a credential."""

    id: str = ""
    credential_id: str = ""
    rating: PostureRating = PostureRating.GOOD
    issues: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    last_rotation_days: int = 0
    overprivileged: bool = False


class JITCredential(BaseModel):
    """A just-in-time credential issued to a requester."""

    id: str = ""
    credential_type: CredentialType = CredentialType.API_KEY
    scope: list[str] = Field(default_factory=list)
    ttl_seconds: int = 3600
    issued_to: str = ""
    issued_at: str = ""
    expires_at: str = ""
    vault_path: str = ""


class RotationResult(BaseModel):
    """Result of a credential rotation operation."""

    id: str = ""
    credential_id: str = ""
    old_hash: str = ""
    new_hash: str = ""
    rotated_at: str = ""
    success: bool = False
    error_message: str = ""


class RevocationResult(BaseModel):
    """Result of a credential revocation operation."""

    id: str = ""
    credential_id: str = ""
    reason: str = ""
    revoked_at: str = ""
    success: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


# --- Main state ---


class CredentialLifecycleState(BaseModel):
    """Main state for the Credential Lifecycle agent graph."""

    request_id: str = ""
    stage: LifecycleStage = LifecycleStage.DISCOVER

    # Input
    tenant_id: str = ""
    scan_scope: list[str] = Field(default_factory=list)

    # Discovery & assessment
    discovered_credentials: list[CredentialRecord] = Field(default_factory=list)
    posture_assessments: list[PostureAssessment] = Field(default_factory=list)

    # Actions
    jit_credentials_issued: list[JITCredential] = Field(default_factory=list)
    rotation_results: list[RotationResult] = Field(default_factory=list)
    revocation_results: list[RevocationResult] = Field(default_factory=list)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
