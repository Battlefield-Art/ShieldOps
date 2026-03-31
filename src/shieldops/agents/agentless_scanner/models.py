"""State models for the Agentless Scanner Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class ASStage(StrEnum):
    """Stages in the agentless scanning lifecycle."""

    DISCOVER_ASSETS = "discover_assets"
    SCAN_CONFIG = "scan_config"
    CHECK_VULNS = "check_vulns"
    ANALYZE_EXPOSURE = "analyze_exposure"
    PRIORITIZE = "prioritize"
    REPORT = "report"


class CloudProvider(StrEnum):
    """Supported cloud providers for agentless scanning."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    KUBERNETES = "kubernetes"
    MULTI_CLOUD = "multi_cloud"


class AssetCategory(StrEnum):
    """Cloud asset categories for scanning."""

    COMPUTE = "compute"
    STORAGE = "storage"
    NETWORK = "network"
    DATABASE = "database"
    IDENTITY = "identity"
    SERVERLESS = "serverless"


# --- Domain models ---


class CloudAsset(BaseModel):
    """A discovered cloud asset to scan."""

    asset_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    category: AssetCategory = AssetCategory.COMPUTE
    resource_type: str = ""
    region: str = ""
    tags: dict[str, str] = Field(default_factory=dict)
    last_scanned: datetime | None = None


class ConfigFinding(BaseModel):
    """A configuration finding from scanning."""

    finding_id: str = ""
    asset_id: str = ""
    rule_id: str = ""
    severity: str = "medium"
    description: str = ""
    remediation: str = ""
    compliant: bool = False


class VulnerabilityFinding(BaseModel):
    """A vulnerability discovered via snapshot analysis."""

    vuln_id: str = ""
    asset_id: str = ""
    cve_id: str = ""
    severity: str = "medium"
    cvss_score: float = 0.0
    package_name: str = ""
    installed_version: str = ""
    fixed_version: str = ""


class ExposureAnalysis(BaseModel):
    """Exposure analysis for discovered assets."""

    analysis_id: str = ""
    public_exposure: bool = False
    internet_facing: bool = False
    attack_surface_score: float = 0.0
    exposure_paths: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class PrioritizedFinding(BaseModel):
    """A finding prioritized by risk context."""

    finding_id: str = ""
    original_severity: str = "medium"
    adjusted_severity: str = "medium"
    risk_score: float = 0.0
    exploitability: str = "low"
    business_impact: str = "low"
    remediation_priority: int = 0


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the agentless scanner workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class AgentlessScannerState(BaseModel):
    """Full state for an agentless scanner run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: ASStage = ASStage.DISCOVER_ASSETS

    # Inputs
    scan_name: str = ""
    target_providers: list[CloudProvider] = Field(
        default_factory=list,
    )
    target_regions: list[str] = Field(default_factory=list)
    scan_scope: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    assets: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    config_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    vuln_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    exposure_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    prioritized: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_assets: int = 0
    total_findings: int = 0
    critical_findings: int = 0
    scan_coverage: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
