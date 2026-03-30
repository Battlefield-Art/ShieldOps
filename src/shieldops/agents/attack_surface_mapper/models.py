"""State models for the Attack Surface Mapper Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class ASMStage(StrEnum):
    """Workflow stages for attack surface mapping."""

    DISCOVER_ASSETS = "discover_assets"
    CLASSIFY_EXPOSURE = "classify_exposure"
    ASSESS_RISK = "assess_risk"
    MAP_ATTACK_PATHS = "map_attack_paths"
    RECOMMEND_REMEDIATION = "recommend_remediation"
    REPORT = "report"


class ExposureLevel(StrEnum):
    """Network exposure classification for assets."""

    INTERNET_FACING = "internet_facing"
    DMZ = "dmz"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    AIRGAPPED = "airgapped"


class AssetType(StrEnum):
    """Types of assets discovered during surface mapping."""

    WEB_APP = "web_app"
    API_ENDPOINT = "api_endpoint"
    DATABASE = "database"
    STORAGE = "storage"
    DNS = "dns"
    CERTIFICATE = "certificate"
    CLOUD_SERVICE = "cloud_service"


# ── Domain Models ─────────────────────────────────────


class DiscoveredAsset(BaseModel):
    """An asset discovered during attack surface mapping."""

    asset_id: str = ""
    asset_type: AssetType = AssetType.WEB_APP
    hostname: str = ""
    ip_address: str = ""
    port: int = 0
    service: str = ""
    owner: str = ""
    is_shadow_it: bool = False
    last_seen: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExposureClassification(BaseModel):
    """Exposure classification for a discovered asset."""

    asset_id: str = ""
    exposure_level: ExposureLevel = ExposureLevel.INTERNAL
    is_forgotten: bool = False
    is_misconfigured: bool = False
    open_ports: list[int] = Field(default_factory=list)
    tls_valid: bool = True
    auth_required: bool = True
    findings: list[str] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    """Risk assessment for an exposed asset."""

    asset_id: str = ""
    risk_score: float = 0.0
    cvss_max: float = 0.0
    exploitability: str = "low"
    business_impact: str = "low"
    cve_ids: list[str] = Field(default_factory=list)
    reasoning: str = ""


class AttackPath(BaseModel):
    """A mapped attack path through discovered assets."""

    path_id: str = ""
    entry_point: str = ""
    target: str = ""
    hops: list[str] = Field(default_factory=list)
    likelihood: float = 0.0
    impact: str = "low"
    technique_ids: list[str] = Field(default_factory=list)
    description: str = ""


class RemediationRecommendation(BaseModel):
    """Remediation recommendation for an exposed asset."""

    rec_id: str = ""
    asset_id: str = ""
    priority: str = "medium"
    action: str = ""
    effort: str = "medium"
    risk_reduction: float = 0.0
    description: str = ""


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the mapper workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class AttackSurfaceMapperState(BaseModel):
    """Full state for the Attack Surface Mapper workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: ASMStage = ASMStage.DISCOVER_ASSETS
    scan_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Discovery
    discovered_assets: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    shadow_it_count: int = 0

    # Classification
    exposure_classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    internet_facing_count: int = 0

    # Risk
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    max_risk_score: float = 0.0

    # Attack paths
    attack_paths: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Remediation
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
