"""State models for the Patch Orchestrator Agent."""

from __future__ import annotations

from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class PatchStage(StrEnum):
    """Stages of the patch orchestration workflow."""

    INVENTORY_SYSTEMS = "inventory_systems"
    ASSESS_PATCHES = "assess_patches"
    PRIORITIZE_DEPLOYMENT = "prioritize_deployment"
    DEPLOY_PATCHES = "deploy_patches"
    VERIFY_SUCCESS = "verify_success"
    REPORT = "report"


class PatchPriority(StrEnum):
    """Priority levels for patch deployment."""

    EMERGENCY = "emergency"
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DeploymentStatus(StrEnum):
    """Status of a patch deployment."""

    PENDING = "pending"
    DEPLOYING = "deploying"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class SystemInventory(BaseModel):
    """Inventory of a system targeted for patching."""

    id: str = Field(default_factory=lambda: f"sys-{uuid4().hex[:12]}")
    hostname: str
    os_type: str = ""
    os_version: str = ""
    environment: str = "production"
    is_critical: bool = False
    current_patch_level: str = ""
    tags: list[str] = Field(default_factory=list)


class PatchAssessment(BaseModel):
    """Assessment of a patch against target systems."""

    id: str = Field(default_factory=lambda: f"patch-{uuid4().hex[:12]}")
    cve_id: str = ""
    patch_name: str
    severity: PatchPriority = PatchPriority.MEDIUM
    affected_systems: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    requires_reboot: bool = False
    compatible: bool = True


class DeploymentPlan(BaseModel):
    """Plan for staged patch deployment."""

    id: str = Field(default_factory=lambda: f"plan-{uuid4().hex[:12]}")
    canary_targets: list[str] = Field(default_factory=list)
    rollout_targets: list[str] = Field(default_factory=list)
    rollback_plan: str = ""
    approval_required: bool = False
    estimated_duration_min: int = 30


class PatchDeployment(BaseModel):
    """Record of a single patch deployment."""

    id: str = Field(default_factory=lambda: f"dep-{uuid4().hex[:12]}")
    system_id: str
    patch_id: str
    status: DeploymentStatus = DeploymentStatus.PENDING
    started_at: float = 0.0
    completed_at: float = 0.0
    error_message: str = ""
    is_canary: bool = False


class VerificationResult(BaseModel):
    """Result of post-patch verification."""

    id: str = Field(default_factory=lambda: f"ver-{uuid4().hex[:12]}")
    deployment_id: str
    system_id: str
    patch_applied: bool = False
    service_healthy: bool = False
    rollback_needed: bool = False
    details: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class PatchOrchestratorState(BaseModel):
    """Full state of the patch orchestration workflow."""

    # Input
    tenant_id: str = ""
    request_id: str = Field(default_factory=lambda: f"req-{uuid4().hex[:12]}")
    target_environment: str = "production"

    # Pipeline
    systems_inventoried: list[SystemInventory] = Field(default_factory=list)
    patches_assessed: list[PatchAssessment] = Field(default_factory=list)
    deployment_plan: DeploymentPlan | None = None
    deployments: list[PatchDeployment] = Field(default_factory=list)
    verifications: list[VerificationResult] = Field(default_factory=list)

    # Counters
    patched_count: int = 0
    failed_count: int = 0
    rollback_count: int = 0

    # Report
    report_summary: str = ""

    # Metadata
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_stage: str = "init"
    error: str = ""
    duration_ms: int = 0
