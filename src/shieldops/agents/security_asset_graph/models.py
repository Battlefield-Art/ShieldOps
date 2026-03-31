"""State models for the Security Asset Graph Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class SAGStage(StrEnum):
    """Stages in the security asset graph lifecycle."""

    DISCOVER_ASSETS = "discover_assets"
    MAP_DEPENDENCIES = "map_dependencies"
    ANALYZE_IMPACT = "analyze_impact"
    IDENTIFY_CRITICAL_PATHS = "identify_critical_paths"
    SCORE_RISK = "score_risk"
    REPORT = "report"


class AssetType(StrEnum):
    """Type of infrastructure asset."""

    SERVER = "server"
    DATABASE = "database"
    APPLICATION = "application"
    NETWORK = "network"
    CONTAINER = "container"
    IDENTITY = "identity"


class RelationshipType(StrEnum):
    """Type of dependency relationship between assets."""

    DEPENDS_ON = "depends_on"
    AUTHENTICATES_TO = "authenticates_to"
    ROUTES_TRAFFIC = "routes_traffic"
    STORES_DATA = "stores_data"
    MANAGES = "manages"
    EXPOSES = "exposes"


# --- Domain models ---


class AssetNode(BaseModel):
    """An asset in the dependency graph."""

    asset_id: str = ""
    name: str = ""
    asset_type: AssetType = AssetType.SERVER
    environment: str = "production"
    owner: str = ""
    criticality: str = "medium"
    tags: list[str] = Field(default_factory=list)


class DependencyEdge(BaseModel):
    """A dependency relationship between two assets."""

    source_id: str = ""
    target_id: str = ""
    relationship: RelationshipType = RelationshipType.DEPENDS_ON
    weight: float = 1.0
    bidirectional: bool = False
    protocol: str = ""


class ImpactAnalysis(BaseModel):
    """Blast radius analysis for an asset failure."""

    asset_id: str = ""
    blast_radius: int = 0
    affected_assets: list[str] = Field(default_factory=list)
    cascading_failures: int = 0
    recovery_time_estimate: str = ""
    impact_score: float = 0.0


class CriticalPath(BaseModel):
    """A critical dependency path in the graph."""

    path_id: str = ""
    nodes: list[str] = Field(default_factory=list)
    single_points_of_failure: list[str] = Field(
        default_factory=list,
    )
    path_risk: float = 0.0
    redundancy_score: float = 0.0


class RiskScore(BaseModel):
    """Aggregated risk score for an asset or path."""

    entity_id: str = ""
    risk_score: float = 0.0
    factors: list[str] = Field(default_factory=list)
    mitigation_recommendations: list[str] = Field(
        default_factory=list,
    )


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the asset graph workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityAssetGraphState(BaseModel):
    """Full state for a security asset graph run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SAGStage = SAGStage.DISCOVER_ASSETS

    # Inputs
    target_environment: str = "production"
    asset_types: list[str] = Field(default_factory=list)
    scope: dict[str, Any] = Field(default_factory=dict)
    depth_limit: int = 5

    # Pipeline fields
    assets: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    dependencies: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    impact_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    critical_paths: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_scores: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_assets: int = 0
    total_dependencies: int = 0
    critical_path_count: int = 0
    overall_risk: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
