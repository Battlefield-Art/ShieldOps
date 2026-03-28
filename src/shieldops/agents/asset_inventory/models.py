"""Asset Inventory Agent — Pydantic state and data models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class InventoryStage(StrEnum):
    DISCOVER = "discover"
    CLASSIFY = "classify"
    ASSIGN_OWNERS = "assign_owners"
    ASSESS_RISK = "assess_risk"
    RECONCILE = "reconcile"
    REPORT = "report"


class AssetType(StrEnum):
    SERVER = "server"
    CONTAINER = "container"
    DATABASE = "database"
    API_ENDPOINT = "api_endpoint"
    STORAGE = "storage"
    NETWORK = "network"
    AI_MODEL = "ai_model"
    SERVICE_ACCOUNT = "service_account"
    UNKNOWN = "unknown"


class Criticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class DiscoveredAsset(BaseModel):
    """An asset discovered during infrastructure scanning."""

    id: str = ""
    name: str = ""
    asset_type: AssetType = AssetType.UNKNOWN
    cloud_provider: str = ""
    region: str = ""
    ip_address: str = ""
    tags: dict[str, str] = Field(default_factory=dict)
    discovered_at: datetime | None = None
    is_managed: bool = False
    source: str = ""


class ClassifiedAsset(BaseModel):
    """An asset after classification with criticality and metadata."""

    asset_id: str = ""
    asset_type: AssetType = AssetType.UNKNOWN
    criticality: Criticality = Criticality.MEDIUM
    data_sensitivity: str = ""
    internet_facing: bool = False
    compliance_scope: list[str] = Field(default_factory=list)
    classification_rationale: str = ""


class OwnerAssignment(BaseModel):
    """Ownership assignment for a discovered asset."""

    asset_id: str = ""
    owner_team: str = ""
    owner_email: str = ""
    backup_owner: str = ""
    assignment_method: str = ""
    confidence: float = 0.0


class RiskAssessment(BaseModel):
    """Risk assessment for a classified asset."""

    asset_id: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    vulnerabilities: int = 0
    misconfigurations: int = 0
    exposure_level: str = ""
    recommendations: list[str] = Field(default_factory=list)


class ReconciliationResult(BaseModel):
    """Result of reconciling discovered assets against known inventory."""

    new_assets: int = 0
    removed_assets: int = 0
    changed_assets: int = 0
    unmanaged_assets: int = 0
    stale_assets: int = 0
    drift_items: list[str] = Field(default_factory=list)


class AssetInventoryState(BaseModel):
    """Main state for the Asset Inventory agent graph."""

    request_id: str = ""
    tenant_id: str = ""
    stage: InventoryStage = InventoryStage.DISCOVER

    # Discovery results
    discovered_assets: list[dict[str, Any]] = Field(default_factory=list)

    # Classification results
    classifications: list[dict[str, Any]] = Field(default_factory=list)

    # Owner assignments
    owner_assignments: list[dict[str, Any]] = Field(default_factory=list)

    # Risk assessments
    risk_assessments: list[dict[str, Any]] = Field(default_factory=list)

    # Reconciliation
    reconciliation: dict[str, Any] = Field(default_factory=dict)

    # Report
    summary: str = ""
    total_assets: int = 0
    unmanaged_count: int = 0
    critical_count: int = 0

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
