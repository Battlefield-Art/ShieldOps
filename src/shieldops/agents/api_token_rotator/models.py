"""API Token Rotator Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ATRStage(StrEnum):
    DISCOVER_TOKENS = "discover_tokens"
    AUDIT_AGE = "audit_age"
    ASSESS_RISK = "assess_risk"
    GENERATE_NEW = "generate_new"
    ROTATE = "rotate"
    REPORT = "report"


class TokenType(StrEnum):
    API_KEY = "api_key"
    OAUTH_TOKEN = "oauth_token"
    SERVICE_ACCOUNT = "service_account"
    JWT_SECRET = "jwt_secret"
    WEBHOOK_SECRET = "webhook_secret"
    PAT = "personal_access_token"


class TokenRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


class TokenRecord(BaseModel):
    """A discovered API token or credential."""

    id: str = ""
    name: str = ""
    token_type: TokenType = TokenType.API_KEY
    service: str = ""
    owner: str = ""
    created_at: str = ""
    last_used: str = ""
    age_days: int = 0
    scopes: list[str] = Field(default_factory=list)
    is_active: bool = True


class AgeAudit(BaseModel):
    """Result of a token age audit."""

    id: str = ""
    token_id: str = ""
    age_days: int = 0
    max_age_policy: int = 90
    is_stale: bool = False
    last_rotated: str = ""
    rotation_overdue: bool = False


class RiskAssessment(BaseModel):
    """Risk assessment for a token."""

    id: str = ""
    token_id: str = ""
    risk: TokenRisk = TokenRisk.MEDIUM
    overprivileged: bool = False
    unused_scopes: list[str] = Field(default_factory=list)
    exposure_vector: str = ""
    recommendation: str = ""


class RotationResult(BaseModel):
    """Result of a token rotation."""

    id: str = ""
    token_id: str = ""
    old_token_revoked: bool = False
    new_token_generated: bool = False
    service_updated: bool = False
    zero_downtime: bool = True
    rollback_available: bool = True


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class APITokenRotatorState(BaseModel):
    """Main state for the API Token Rotator agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: ATRStage = ATRStage.DISCOVER_TOKENS

    tokens: list[TokenRecord] = Field(default_factory=list)
    age_audits: list[AgeAudit] = Field(default_factory=list)
    risk_assessments: list[RiskAssessment] = Field(default_factory=list)
    rotations: list[RotationResult] = Field(default_factory=list)

    report: str = ""
    total_tokens_discovered: int = 0
    tokens_rotated: int = 0

    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    error: str = ""
