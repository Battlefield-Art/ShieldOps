"""State models for the Exposure Management Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ────────────────────────────────────────────────


class ExposureStage(StrEnum):
    """Workflow stages for exposure management."""

    DISCOVER_ATTACK_SURFACE = "discover_attack_surface"
    ENUMERATE_ASSETS = "enumerate_assets"
    ASSESS_EXPOSURES = "assess_exposures"
    PRIORITIZE_RISKS = "prioritize_risks"
    RECOMMEND_REMEDIATION = "recommend_remediation"
    REPORT = "report"


class SurfaceType(StrEnum):
    """Types of attack surfaces being assessed."""

    EXTERNAL_NETWORK = "external_network"
    CLOUD_INFRASTRUCTURE = "cloud_infrastructure"
    IDENTITY_SURFACE = "identity_surface"
    AI_ENDPOINT = "ai_endpoint"
    CODE_REPOSITORY = "code_repository"
    API_SURFACE = "api_surface"


class ExposureSeverity(StrEnum):
    """Severity levels for exposure findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# ── Domain Models ───────────────────────────────────────────


class AttackSurface(BaseModel):
    """A discovered attack surface."""

    surface_id: str = ""
    surface_type: str = SurfaceType.EXTERNAL_NETWORK
    name: str = ""
    description: str = ""
    asset_count: int = 0
    exposure_count: int = 0
    risk_score: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssetInventory(BaseModel):
    """An enumerated asset within an attack surface."""

    asset_id: str = ""
    surface_type: str = SurfaceType.EXTERNAL_NETWORK
    hostname: str = ""
    ip_address: str = ""
    cloud_provider: str = ""
    asset_class: str = ""
    is_ai_asset: bool = False
    mcp_exposed: bool = False
    rag_public: bool = False
    llm_endpoint: bool = False
    tags: list[str] = Field(default_factory=list)
    risk_score: float = 0.0


class ExposureAssessment(BaseModel):
    """An assessed exposure on an asset."""

    exposure_id: str = ""
    asset_id: str = ""
    surface_type: str = SurfaceType.EXTERNAL_NETWORK
    severity: str = ExposureSeverity.MEDIUM
    title: str = ""
    description: str = ""
    cvss_score: float = 0.0
    epss_score: float = 0.0
    cisa_kev: bool = False
    exploitability: str = "unknown"
    attack_path: str = ""
    blast_radius: str = ""


class RiskPrioritization(BaseModel):
    """A prioritized risk entry combining exposure + context."""

    rank: int = 0
    exposure_id: str = ""
    asset_id: str = ""
    severity: str = ExposureSeverity.MEDIUM
    business_impact: str = "unknown"
    composite_score: float = 0.0
    epss_score: float = 0.0
    cisa_kev: bool = False
    attack_path_depth: int = 0
    recommended_sla_hours: int = 72


class RemediationRecommendation(BaseModel):
    """A remediation recommendation for a prioritized risk."""

    recommendation_id: str = ""
    exposure_id: str = ""
    action: str = ""
    priority: str = "medium"
    effort_hours: float = 0.0
    automation_possible: bool = False
    runbook_id: str = ""
    reasoning: str = ""


# ── Reasoning Step ──────────────────────────────────────────


class ExposureReasoningStep(BaseModel):
    """Audit trail entry for the exposure workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


# ── LangGraph State ─────────────────────────────────────────


class ExposureManagementState(BaseModel):
    """Full state for an exposure management workflow run."""

    # Input
    tenant_id: str = ""
    assessment_id: str = ""
    scan_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Stage outputs
    surfaces_discovered: list[AttackSurface] = Field(
        default_factory=list,
    )
    assets_enumerated: list[AssetInventory] = Field(
        default_factory=list,
    )
    exposures_assessed: list[ExposureAssessment] = Field(
        default_factory=list,
    )
    prioritized_risks: list[RiskPrioritization] = Field(
        default_factory=list,
    )
    remediation_recommendations: list[RemediationRecommendation] = Field(default_factory=list)

    # Aggregates
    total_exposure_score: float = 0.0
    surface_count: int = 0
    asset_count: int = 0
    critical_count: int = 0
    ai_exposure_count: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ExposureReasoningStep] = Field(
        default_factory=list,
    )
    current_stage: str = "init"
    error: str = ""
