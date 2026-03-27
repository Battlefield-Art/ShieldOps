"""State models for the OAuth Grant Analyzer Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AnalyzerStage(StrEnum):
    """Stages of the OAuth grant analysis workflow."""

    DISCOVER_GRANTS = "discover_grants"
    CLASSIFY_PERMISSIONS = "classify_permissions"
    ASSESS_RISK = "assess_risk"
    DETECT_ANOMALIES = "detect_anomalies"
    RECOMMEND_ACTIONS = "recommend_actions"
    REPORT = "report"


class GrantStatus(StrEnum):
    """Status of an OAuth grant."""

    ACTIVE = "active"
    STALE = "stale"
    REVOKED = "revoked"
    SUSPICIOUS = "suspicious"
    PENDING_REVIEW = "pending_review"


class PermissionScope(StrEnum):
    """Classification of OAuth permission scope breadth."""

    READ_ONLY = "read_only"
    READ_WRITE = "read_write"
    ADMIN = "admin"
    DELEGATED = "delegated"
    FULL_ACCESS = "full_access"


class OAuthGrant(BaseModel):
    """A single OAuth grant discovered across SaaS or cloud providers."""

    id: str = ""
    app_name: str = ""
    app_id: str = ""
    provider: str = ""
    granted_to: str = ""
    granted_by: str = ""
    scopes: list[str] = Field(default_factory=list)
    permission_scope: PermissionScope = PermissionScope.READ_ONLY
    status: GrantStatus = GrantStatus.ACTIVE
    created_at: float = 0.0
    last_used: float = 0.0
    risk_score: float = 0.0


class PermissionClassification(BaseModel):
    """Classification result for an OAuth grant's actual vs needed permissions."""

    id: str = ""
    grant_id: str = ""
    classified_scope: PermissionScope = PermissionScope.READ_ONLY
    overprivileged: bool = False
    unused_scopes: list[str] = Field(default_factory=list)
    risk_factors: list[str] = Field(default_factory=list)


class GrantAnomaly(BaseModel):
    """An anomaly detected in OAuth grant behavior or configuration."""

    id: str = ""
    grant_id: str = ""
    anomaly_type: str = ""
    description: str = ""
    severity: str = "medium"
    confidence: float = 0.0
    detected_at: float = 0.0


class GrantRecommendation(BaseModel):
    """A remediation recommendation for an OAuth grant."""

    id: str = ""
    grant_id: str = ""
    action: str = ""
    reason: str = ""
    priority: str = "medium"
    auto_executable: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step: int = 0
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class OAuthAnalyzerState(BaseModel):
    """Full state of an OAuth grant analysis workflow."""

    # Input
    request_id: str = ""
    stage: AnalyzerStage = AnalyzerStage.DISCOVER_GRANTS
    tenant_id: str = ""
    scan_scope: list[str] = Field(default_factory=list)

    # Discovery
    discovered_grants: list[OAuthGrant] = Field(default_factory=list)

    # Classification
    permission_classifications: list[PermissionClassification] = Field(default_factory=list)

    # Anomalies
    anomalies: list[GrantAnomaly] = Field(default_factory=list)

    # Recommendations
    recommendations: list[GrantRecommendation] = Field(default_factory=list)

    # Aggregated stats
    stats: dict[str, Any] = Field(default_factory=dict)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = "init"
    session_start: float = 0.0
    session_duration_ms: int = 0
    error: str = ""
