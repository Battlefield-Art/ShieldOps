"""SaaS Security Posture Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SSPStage(StrEnum):
    DISCOVER_APPS = "discover_apps"
    AUDIT_CONFIG = "audit_config"
    CHECK_SHARING = "check_sharing"
    ASSESS_RISK = "assess_risk"
    REMEDIATE = "remediate"
    REPORT = "report"


class SaaSRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SharingScope(StrEnum):
    PUBLIC = "public"
    EXTERNAL = "external"
    INTERNAL = "internal"
    PRIVATE = "private"
    RESTRICTED = "restricted"


class SaaSApp(BaseModel):
    """A discovered SaaS application."""

    id: str = ""
    name: str = ""
    vendor: str = ""
    category: str = ""
    users_count: int = 0
    oauth_scopes: list[str] = Field(default_factory=list)
    is_sanctioned: bool = True
    sso_enabled: bool = False
    mfa_enforced: bool = False


class ConfigFinding(BaseModel):
    """A SaaS misconfiguration finding."""

    id: str = ""
    app_name: str = ""
    check_name: str = ""
    severity: SaaSRisk = SaaSRisk.MEDIUM
    description: str = ""
    current_value: str = ""
    expected_value: str = ""
    remediation: str = ""


class SharingExposure(BaseModel):
    """A data sharing exposure finding."""

    id: str = ""
    app_name: str = ""
    resource: str = ""
    scope: SharingScope = SharingScope.INTERNAL
    shared_with: str = ""
    owner: str = ""
    sensitive_data: bool = False
    last_accessed: str = ""


class RiskAssessment(BaseModel):
    """Risk assessment result for a SaaS app."""

    id: str = ""
    app_name: str = ""
    overall_risk: SaaSRisk = SaaSRisk.MEDIUM
    risk_score: float = 0.0
    misconfig_count: int = 0
    sharing_exposures: int = 0
    compliance_gaps: list[str] = Field(default_factory=list)


class RemediationAction(BaseModel):
    """A remediation action taken."""

    id: str = ""
    app_name: str = ""
    finding_id: str = ""
    action: str = ""
    status: str = ""
    automated: bool = False
    rollback_available: bool = True


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SaaSSecurityPostureState(BaseModel):
    """Main state for the SaaS Security Posture agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SSPStage = SSPStage.DISCOVER_APPS

    apps: list[dict[str, Any]] = Field(default_factory=list)
    config_findings: list[dict[str, Any]] = Field(default_factory=list)
    sharing_exposures: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    remediations: list[dict[str, Any]] = Field(default_factory=list)

    report: str = ""
    total_apps: int = 0
    misconfigs_found: int = 0
    high_risk_apps: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
