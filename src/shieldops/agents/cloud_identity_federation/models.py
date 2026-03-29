"""Cloud Identity Federation Agent — Pydantic state and data models."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class FederationStage(StrEnum):
    DISCOVER_IDENTITIES = "discover_identities"
    MAP_FEDERATIONS = "map_federations"
    DETECT_MISCONFIGS = "detect_misconfigs"
    ANALYZE_TRUST = "analyze_trust"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class IdentityProvider(StrEnum):
    OKTA = "okta"
    AZURE_AD = "azure_ad"
    GOOGLE_WORKSPACE = "google_workspace"
    AWS_IAM = "aws_iam"
    PING_IDENTITY = "ping_identity"
    CUSTOM_SAML = "custom_saml"


class FederationRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FederatedIdentity(BaseModel):
    """A federated identity across cloud providers."""

    id: str = ""
    identity_provider: IdentityProvider = IdentityProvider.OKTA
    principal_name: str = ""
    email: str = ""
    cloud_mappings: list[dict[str, str]] = Field(default_factory=list)
    mfa_enabled: bool = True
    last_login: float = Field(default_factory=time.time)
    roles: list[str] = Field(default_factory=list)


class FederationMapping(BaseModel):
    """A federation trust mapping between providers."""

    id: str = ""
    source_idp: str = ""
    target_cloud: str = ""
    trust_type: str = ""
    protocol: str = "saml"
    attribute_mappings: dict[str, str] = Field(default_factory=dict)
    session_duration_hours: int = 1
    mfa_required: bool = True


class SsoMisconfiguration(BaseModel):
    """An SSO misconfiguration finding."""

    id: str = ""
    federation_id: str = ""
    misconfig_type: str = ""
    severity: FederationRisk = FederationRisk.MEDIUM
    description: str = ""
    affected_users: int = 0
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    remediation: str = ""


class TrustAnalysis(BaseModel):
    """Trust chain analysis result."""

    id: str = ""
    trust_chain: list[str] = Field(default_factory=list)
    trust_score: float = Field(default=0.0, ge=0.0, le=100.0)
    weaknesses: list[str] = Field(default_factory=list)
    cross_cloud_risks: list[str] = Field(default_factory=list)
    description: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudIdentityFederationState(BaseModel):
    """Main state for Cloud Identity Federation agent graph."""

    request_id: str = ""
    stage: FederationStage = FederationStage.DISCOVER_IDENTITIES
    tenant_id: str = ""
    identity_providers: list[str] = Field(default_factory=list)

    # Pipeline data
    federated_identities: list[dict[str, Any]] = Field(default_factory=list)
    federation_mappings: list[dict[str, Any]] = Field(default_factory=list)
    sso_misconfigs: list[dict[str, Any]] = Field(default_factory=list)
    trust_analyses: list[dict[str, Any]] = Field(default_factory=list)

    # Risk assessment
    risk_score: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""

    # Timing
    session_start: float = Field(default_factory=time.time)
    session_duration_ms: float = 0.0

    # Error
    error: str = ""
