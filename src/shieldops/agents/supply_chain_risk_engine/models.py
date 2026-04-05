"""State models for the Supply Chain Risk Engine Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SCREStage(StrEnum):
    """Stages of the supply chain risk assessment lifecycle."""

    INVENTORY_DEPENDENCIES = "inventory_dependencies"
    SCAN_VULNERABILITIES = "scan_vulnerabilities"
    ASSESS_RISK = "assess_risk"
    MAP_BLAST_RADIUS = "map_blast_radius"
    RECOMMEND_MITIGATIONS = "recommend_mitigations"
    REPORT = "report"


class DependencyType(StrEnum):
    """Types of software dependencies tracked."""

    DIRECT = "direct"
    TRANSITIVE = "transitive"
    CONTAINER_IMAGE = "container_image"
    OS_PACKAGE = "os_package"
    THIRD_PARTY_API = "third_party_api"
    BUILD_TOOL = "build_tool"
    PLUGIN = "plugin"
    FIRMWARE = "firmware"


class SupplyChainRisk(StrEnum):
    """Risk classification for supply chain components."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class DependencyRecord(BaseModel):
    """A single dependency in the software supply chain."""

    record_id: str = ""
    name: str = ""
    version: str = ""
    dependency_type: DependencyType = DependencyType.DIRECT
    source: str = ""
    license_type: str = ""
    maintainer: str = ""
    last_updated: datetime | None = None
    is_pinned: bool = False
    depth: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityScan(BaseModel):
    """Vulnerability scan result for a dependency."""

    scan_id: str = ""
    record_id: str = ""
    cve_id: str = ""
    severity: str = "medium"
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    description: str = ""
    fix_available: bool = False
    fix_version: str = ""
    exploitable: bool = False


class RiskAssessment(BaseModel):
    """Risk assessment for a dependency or group."""

    assessment_id: str = ""
    record_id: str = ""
    risk_level: SupplyChainRisk = SupplyChainRisk.UNKNOWN
    overall_score: float = Field(default=0.0, ge=0.0, le=1.0)
    vulnerability_count: int = 0
    exploitable_count: int = 0
    factors: list[str] = Field(default_factory=list)


class BlastRadiusMapping(BaseModel):
    """Blast radius analysis for a vulnerable dependency."""

    mapping_id: str = ""
    record_id: str = ""
    affected_services: list[str] = Field(default_factory=list)
    affected_environments: list[str] = Field(default_factory=list)
    downstream_count: int = 0
    blast_radius: str = "low"


class MitigationRecommendation(BaseModel):
    """Recommendation for mitigating a supply chain risk."""

    recommendation_id: str = ""
    record_id: str = ""
    priority: str = "medium"
    action: str = ""
    description: str = ""
    effort: str = "low"
    automated: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SupplyChainRiskEngineState(BaseModel):
    """Full LangGraph state for the Supply Chain Risk Engine."""

    # Input
    request_id: str = ""
    tenant_id: str = ""
    stage: SCREStage = SCREStage.INVENTORY_DEPENDENCIES
    config: dict[str, Any] = Field(default_factory=dict)

    # Pipeline fields
    dependencies: list[dict[str, Any]] = Field(default_factory=list)
    vulnerability_scans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    blast_radius_mappings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    mitigations: list[dict[str, Any]] = Field(default_factory=list)
    report: dict[str, Any] = Field(default_factory=dict)

    # Metrics
    dependency_count: int = 0
    vulnerability_count: int = 0
    critical_count: int = 0

    # Metadata
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
