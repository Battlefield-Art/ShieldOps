"""State models for the Cloud Network Analyzer Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class CNAStage(StrEnum):
    """Stages in the cloud network analysis lifecycle."""

    DISCOVER_TOPOLOGY = "discover_topology"
    ANALYZE_ROUTES = "analyze_routes"
    CHECK_SEGMENTATION = "check_segmentation"
    DETECT_EXPOSURE = "detect_exposure"
    RECOMMEND = "recommend"
    REPORT = "report"


class CloudProvider(StrEnum):
    """Supported cloud providers for network analysis."""

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    MULTI_CLOUD = "multi_cloud"
    ON_PREMISES = "on_premises"
    HYBRID = "hybrid"


class ExposureLevel(StrEnum):
    """Exposure risk levels for network resources."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    UNKNOWN = "unknown"


# --- Domain models ---


class NetworkTopology(BaseModel):
    """Discovered cloud network topology."""

    topology_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    vpcs: list[dict[str, Any]] = Field(default_factory=list)
    subnets: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    peering_connections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    endpoints: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_resources: int = 0


class RouteAnalysis(BaseModel):
    """Analysis of route tables and traffic flow."""

    route_table_id: str = ""
    vpc_id: str = ""
    routes: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    anomalies: list[str] = Field(default_factory=list)
    default_route_risk: str = "low"
    internet_facing: bool = False


class SegmentationResult(BaseModel):
    """Network segmentation analysis result."""

    segment_id: str = ""
    name: str = ""
    isolation_score: float = 0.0
    cross_segment_flows: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    violations: list[str] = Field(default_factory=list)
    compliant: bool = True


class ExposureFinding(BaseModel):
    """An exposure finding from network analysis."""

    finding_id: str = ""
    resource_id: str = ""
    resource_type: str = ""
    exposure_level: ExposureLevel = ExposureLevel.UNKNOWN
    open_ports: list[int] = Field(default_factory=list)
    public_ips: list[str] = Field(default_factory=list)
    security_groups: list[str] = Field(
        default_factory=list,
    )
    description: str = ""


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the analyzer workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class CloudNetworkAnalyzerState(BaseModel):
    """Full state for a cloud network analyzer run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: CNAStage = CNAStage.DISCOVER_TOPOLOGY

    # Inputs
    target_provider: CloudProvider = CloudProvider.AWS
    target_vpcs: list[str] = Field(default_factory=list)
    scan_scope: dict[str, Any] = Field(
        default_factory=dict,
    )
    compliance_framework: str = ""

    # Pipeline fields
    topology: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    route_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    segmentation_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    exposure_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_resources: int = 0
    exposure_count: int = 0
    critical_exposures: int = 0
    segmentation_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
