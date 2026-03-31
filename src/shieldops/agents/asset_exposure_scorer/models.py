"""Asset Exposure Scorer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AESStage(StrEnum):
    DISCOVER_ASSETS = "discover_assets"
    FINGERPRINT_SERVICES = "fingerprint_services"
    CHECK_VULNS = "check_vulns"
    SCORE_EXPOSURE = "score_exposure"
    TRACK_CHANGES = "track_changes"
    REPORT = "report"


class AssetType(StrEnum):
    WEB_APP = "web_app"
    API_ENDPOINT = "api_endpoint"
    DATABASE = "database"
    LOAD_BALANCER = "load_balancer"
    STORAGE_BUCKET = "storage_bucket"
    MAIL_SERVER = "mail_server"


class ExposureLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class DiscoveredAsset(BaseModel):
    """An internet-facing asset discovered during scanning."""

    id: str = ""
    hostname: str = ""
    ip_address: str = ""
    asset_type: AssetType = AssetType.WEB_APP
    port: int = 443
    protocol: str = "https"
    cloud_provider: str = ""
    region: str = ""
    first_seen: str = ""


class ServiceFingerprint(BaseModel):
    """Fingerprint of a service running on an exposed asset."""

    id: str = ""
    asset_id: str = ""
    service_name: str = ""
    version: str = ""
    banner: str = ""
    tls_version: str = ""
    certificate_expiry: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    technologies: list[str] = Field(default_factory=list)


class VulnerabilityCheck(BaseModel):
    """A vulnerability check result for an asset."""

    id: str = ""
    asset_id: str = ""
    cve_id: str = ""
    severity: str = "medium"
    cvss_score: float = 0.0
    description: str = ""
    exploitable: bool = False
    patch_available: bool = True


class ExposureScore(BaseModel):
    """Computed exposure score for an asset."""

    id: str = ""
    asset_id: str = ""
    hostname: str = ""
    overall_score: float = 0.0
    vuln_score: float = 0.0
    config_score: float = 0.0
    exposure_level: ExposureLevel = ExposureLevel.MEDIUM
    factors: list[str] = Field(default_factory=list)


class ChangeRecord(BaseModel):
    """A tracked change in exposure over time."""

    id: str = ""
    asset_id: str = ""
    change_type: str = ""
    previous_score: float = 0.0
    current_score: float = 0.0
    delta: float = 0.0
    detected_at: str = ""
    details: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssetExposureScorerState(BaseModel):
    """Main state for the Asset Exposure Scorer agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: AESStage = AESStage.DISCOVER_ASSETS

    assets: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    fingerprints: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    vulnerabilities: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    scores: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    changes: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    report: str = ""
    assets_discovered: int = 0
    critical_exposures: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
