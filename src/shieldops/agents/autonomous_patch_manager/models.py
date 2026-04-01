"""State models for the Autonomous Patch Manager Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# ── StrEnums ──────────────────────────────────────────


class APMStage(StrEnum):
    """Workflow stages for autonomous patch management."""

    SCAN_INVENTORY = "scan_inventory"
    ASSESS_PATCHES = "assess_patches"
    SCHEDULE_DEPLOYMENT = "schedule_deployment"
    EXECUTE_PATCHES = "execute_patches"
    VALIDATE_RESULTS = "validate_results"
    REPORT = "report"


class PatchPriority(StrEnum):
    """Priority level for a patch."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    DEFERRED = "deferred"


class DeploymentStatus(StrEnum):
    """Status of a patch deployment."""

    PENDING = "pending"
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


# ── Domain Models ─────────────────────────────────────


class AssetRecord(BaseModel):
    """An asset in the fleet inventory."""

    asset_id: str = ""
    hostname: str = ""
    os_type: str = ""
    os_version: str = ""
    environment: str = "production"
    last_patched: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class PatchAssessment(BaseModel):
    """Assessment result for a patch."""

    patch_id: str = ""
    cve_id: str = ""
    priority: PatchPriority = PatchPriority.MEDIUM
    affected_assets: int = 0
    risk_score: float = 0.0
    description: str = ""


class DeploymentSchedule(BaseModel):
    """Schedule for a patch deployment."""

    schedule_id: str = ""
    patch_id: str = ""
    target_assets: list[str] = Field(default_factory=list)
    window_start: str = ""
    window_end: str = ""
    status: DeploymentStatus = DeploymentStatus.PENDING


class PatchExecutionResult(BaseModel):
    """Result of executing a patch on an asset."""

    asset_id: str = ""
    patch_id: str = ""
    status: DeploymentStatus = DeploymentStatus.COMPLETED
    duration_ms: int = 0
    rollback_needed: bool = False


class ValidationResult(BaseModel):
    """Validation result after patching."""

    asset_id: str = ""
    patch_id: str = ""
    healthy: bool = True
    checks_passed: int = 0
    checks_total: int = 0
    issues: list[str] = Field(default_factory=list)


# ── Reasoning + State ─────────────────────────────────


class ReasoningStep(BaseModel):
    """Audit trail entry for the patch manager workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class AutonomousPatchManagerState(BaseModel):
    """Full state for the Autonomous Patch Manager workflow."""

    request_id: str = ""
    tenant_id: str = ""
    stage: APMStage = APMStage.SCAN_INVENTORY
    config: dict[str, Any] = Field(default_factory=dict)

    inventory: list[dict[str, Any]] = Field(default_factory=list)
    patch_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    deployment_schedules: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    execution_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    validation_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    report: dict[str, Any] = Field(default_factory=dict)
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
