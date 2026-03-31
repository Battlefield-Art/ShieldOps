"""State models for the Autonomous Patch Manager Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class APMStage(StrEnum):
    """Stages in the autonomous patch management lifecycle."""

    SCAN_INVENTORY = "scan_inventory"
    CHECK_PATCHES = "check_patches"
    ASSESS_RISK = "assess_risk"
    SCHEDULE_DEPLOYMENT = "schedule_deployment"
    DEPLOY = "deploy"
    REPORT = "report"


class PatchSeverity(StrEnum):
    """Severity classification for patches."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class DeploymentStrategy(StrEnum):
    """Patch deployment strategy types."""

    CANARY = "canary"
    ROLLING = "rolling"
    BLUE_GREEN = "blue_green"
    IMMEDIATE = "immediate"
    MAINTENANCE_WINDOW = "maintenance_window"
    MANUAL = "manual"


# --- Domain models ---


class AssetInventory(BaseModel):
    """An asset in the patch management inventory."""

    asset_id: str = ""
    hostname: str = ""
    os_type: str = ""
    os_version: str = ""
    environment: str = "production"
    last_patched: datetime | None = None
    pending_patches: int = 0
    criticality: str = "medium"


class PatchInfo(BaseModel):
    """Information about an available patch."""

    patch_id: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    severity: PatchSeverity = PatchSeverity.MEDIUM
    affected_software: str = ""
    version_fixed: str = ""
    release_date: datetime | None = None
    requires_reboot: bool = False
    size_mb: float = 0.0


class RiskAssessment(BaseModel):
    """Risk assessment for applying a patch."""

    patch_id: str = ""
    risk_score: float = 0.0
    compatibility_score: float = 1.0
    rollback_available: bool = True
    dependency_conflicts: list[str] = Field(
        default_factory=list,
    )
    blast_radius: int = 0
    recommendation: str = "approve"


class DeploymentSchedule(BaseModel):
    """Scheduled patch deployment plan."""

    schedule_id: str = ""
    strategy: DeploymentStrategy = DeploymentStrategy.ROLLING
    target_assets: list[str] = Field(default_factory=list)
    patches: list[str] = Field(default_factory=list)
    scheduled_at: datetime | None = None
    maintenance_window: str = ""
    canary_percentage: float = 0.1
    rollback_trigger: str = "error_rate > 5%"


class DeploymentResult(BaseModel):
    """Result of a patch deployment operation."""

    deployment_id: str = ""
    patch_id: str = ""
    assets_targeted: int = 0
    assets_succeeded: int = 0
    assets_failed: int = 0
    rollback_triggered: bool = False
    duration_ms: int = 0
    errors: list[str] = Field(default_factory=list)


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the patch manager workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class AutonomousPatchManagerState(BaseModel):
    """Full state for an autonomous patch manager run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: APMStage = APMStage.SCAN_INVENTORY

    # Inputs
    scan_name: str = ""
    target_environments: list[str] = Field(
        default_factory=list,
    )
    strategy: DeploymentStrategy = DeploymentStrategy.ROLLING
    scope: dict[str, Any] = Field(default_factory=dict)
    auto_deploy: bool = False

    # Pipeline fields
    inventory: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    available_patches: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    risk_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    schedules: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    deployments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_assets: int = 0
    patches_available: int = 0
    patches_deployed: int = 0
    deployment_success_rate: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
