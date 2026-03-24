"""State models for the GitOps Agent."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ReconciliationStage(StrEnum):
    """Stages of the GitOps reconciliation workflow."""

    DETECT_DRIFT = "detect_drift"
    PLAN = "plan"
    APPLY = "apply"
    VERIFY = "verify"
    REPORT = "report"


class DriftType(StrEnum):
    """Types of infrastructure drift detected."""

    CONFIG_DRIFT = "config_drift"
    RESOURCE_DRIFT = "resource_drift"
    POLICY_DRIFT = "policy_drift"
    SECRET_DRIFT = "secret_drift"
    VERSION_DRIFT = "version_drift"


class ReconciliationAction(StrEnum):
    """Actions that can be taken to reconcile drift."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    ROLLBACK = "rollback"
    NO_OP = "no_op"


class DriftItem(BaseModel):
    """A single detected drift between desired and actual state."""

    resource_id: str
    resource_type: str
    drift_type: DriftType
    expected_value: str
    actual_value: str
    severity: str = "medium"  # low, medium, high, critical
    namespace: str = ""


class ReconciliationPlan(BaseModel):
    """Plan for reconciling detected drift items."""

    items: list[DriftItem] = Field(default_factory=list)
    actions: list[ReconciliationAction] = Field(default_factory=list)
    estimated_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    requires_approval: bool = False


class ApplyResult(BaseModel):
    """Result of applying a single reconciliation action."""

    resource_id: str
    action: ReconciliationAction
    success: bool
    duration_seconds: float = 0.0
    rollback_available: bool = False
    error: str | None = None


class GitOpsState(BaseModel):
    """Full state of a GitOps reconciliation workflow (LangGraph state)."""

    # Input
    request_id: str = ""
    repo_url: str = ""
    branch: str = "main"
    namespace: str = ""
    dry_run: bool = True

    # Workflow tracking
    stage: ReconciliationStage = ReconciliationStage.DETECT_DRIFT

    # Drift detection
    drift_items: list[DriftItem] = Field(default_factory=list)

    # Planning
    plan: ReconciliationPlan | None = None

    # Apply results
    apply_results: list[ApplyResult] = Field(default_factory=list)

    # Verification
    verification_passed: bool | None = None

    # Outputs
    change_summary: str = ""
    confidence_score: float = 0.0
    reasoning_chain: list[dict[str, Any]] = Field(default_factory=list)

    # Metadata
    error: str | None = None
    current_step: str = "init"
    started_at: datetime | None = None
    duration_ms: int = 0

    # AI Security GitOps
    opa_policies_synced: list[dict[str, Any]] = Field(default_factory=list)
    firewall_policies_synced: list[dict[str, Any]] = Field(default_factory=list)
    mcp_configs_synced: list[dict[str, Any]] = Field(default_factory=list)
    security_config_drifts: list[dict[str, Any]] = Field(default_factory=list)
