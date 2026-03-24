"""NHI Registry Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class NHIType(StrEnum):
    SERVICE_ACCOUNT = "service_account"
    AI_AGENT = "ai_agent"
    CI_CD_TOKEN = "ci_cd_token"  # noqa: S105
    OAUTH_APP = "oauth_app"
    API_KEY = "api_key"
    MCP_CONNECTION = "mcp_connection"
    GITHUB_ACTION = "github_action"
    TERRAFORM_PRINCIPAL = "terraform_principal"
    K8S_SERVICE_ACCOUNT = "k8s_service_account"


class NHIStatus(StrEnum):
    ACTIVE = "active"
    DORMANT = "dormant"
    ORPHANED = "orphaned"
    COMPROMISED = "compromised"
    DECOMMISSIONED = "decommissioned"
    SHADOW = "shadow"


class NHIRisk(StrEnum):
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStage(StrEnum):
    INIT = "init"
    SCANNING = "scanning"
    CLASSIFYING = "classifying"
    ASSESSING = "assessing"
    COMPLETE = "complete"


class NonHumanIdentity(BaseModel):
    """A discovered non-human identity."""

    id: str = ""
    name: str = ""
    nhi_type: NHIType = NHIType.SERVICE_ACCOUNT
    provider: str = ""
    permissions: list[str] = Field(default_factory=list)
    last_used: float = 0.0
    owner: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    status: NHIStatus = NHIStatus.ACTIVE
    created_at: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ShadowAIAgent(BaseModel):
    """A detected unregistered AI/LLM API consumer."""

    id: str = ""
    provider_api_endpoint: str = ""
    detected_via: str = ""
    calling_service: str = ""
    token_type: str = ""
    first_seen: float = 0.0
    request_count: int = 0
    estimated_monthly_cost: float = 0.0


class RemediationRecommendation(BaseModel):
    """A recommended action for an NHI identity."""

    nhi_id: str = ""
    action: str = ""
    priority: str = ""
    reason: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class NHIRegistryState(BaseModel):
    """Main state for the NHI Registry agent graph."""

    request_id: str = ""
    stage: ScanStage = ScanStage.INIT

    # Input
    scan_targets: list[str] = Field(default_factory=list)
    identity_types_filter: list[str] = Field(default_factory=list)
    include_shadow_ai: bool = True

    # Discovery
    discovered_identities: list[NonHumanIdentity] = Field(default_factory=list)
    classified_identities: dict[str, list[NonHumanIdentity]] = Field(default_factory=dict)
    shadow_ai_agents: list[ShadowAIAgent] = Field(default_factory=list)

    # Assessment
    orphaned_identities: list[NonHumanIdentity] = Field(default_factory=list)
    over_privileged_identities: list[NonHumanIdentity] = Field(default_factory=list)
    stale_credentials: list[NonHumanIdentity] = Field(default_factory=list)
    risk_scores: dict[str, float] = Field(default_factory=dict)

    # Response
    remediation_recommendations: list[RemediationRecommendation] = Field(default_factory=list)
    policy_updates: list[dict[str, Any]] = Field(default_factory=list)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
