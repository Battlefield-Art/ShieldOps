"""State models for the Disaster Recovery Agent LangGraph workflow."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DRStage(StrEnum):
    """Stages of the disaster recovery workflow."""

    ASSESS_PLANS = "assess_plans"
    TEST_FAILOVER = "test_failover"
    MEASURE_RTO_RPO = "measure_rto_rpo"
    IDENTIFY_GAPS = "identify_gaps"
    REMEDIATE = "remediate"
    REPORT = "report"


class FailoverType(StrEnum):
    """Types of failover scenarios."""

    DATABASE = "database"
    APPLICATION = "application"
    NETWORK = "network"
    REGION = "region"
    FULL_STACK = "full_stack"


class DRStatus(StrEnum):
    """Status of a disaster recovery plan."""

    TESTED = "tested"
    UNTESTED = "untested"
    FAILED = "failed"
    PARTIAL = "partial"
    EXPIRED = "expired"


class DRPlan(BaseModel):
    """A disaster recovery plan covering one or more services."""

    id: str = ""
    name: str = ""
    services_covered: list[str] = Field(default_factory=list)
    failover_type: FailoverType = FailoverType.APPLICATION
    last_tested: float = 0.0
    rto_target_min: int = 60
    rpo_target_min: int = 15
    status: DRStatus = DRStatus.UNTESTED


class FailoverTest(BaseModel):
    """Result of executing a failover test against a DR plan."""

    id: str = ""
    plan_id: str = ""
    failover_type: FailoverType = FailoverType.APPLICATION
    success: bool = False
    actual_rto_min: float = 0.0
    actual_rpo_min: float = 0.0
    data_loss_detected: bool = False
    duration_min: float = 0.0


class DRGap(BaseModel):
    """An identified gap in disaster recovery coverage or readiness."""

    id: str = ""
    plan_id: str = ""
    gap_type: str = ""
    description: str = ""
    severity: str = "medium"
    remediation: str = ""


class ReasoningStep(BaseModel):
    """Audit trail entry for the disaster recovery workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class DisasterRecoveryState(BaseModel):
    """Full state for a disaster recovery workflow run through the LangGraph workflow."""

    # Input
    tenant_id: str = ""
    plan_ids: list[str] = Field(default_factory=list)

    # Assessment
    plans: list[DRPlan] = Field(default_factory=list)
    assessment_summary: dict[str, Any] = Field(default_factory=dict)

    # Failover testing
    failover_tests: list[FailoverTest] = Field(default_factory=list)

    # RTO/RPO measurement
    rto_rpo_results: dict[str, Any] = Field(default_factory=dict)
    rto_met: bool = False
    rpo_met: bool = False

    # Gap analysis
    gaps: list[DRGap] = Field(default_factory=list)
    has_critical_gaps: bool = False

    # Remediation
    remediation_actions: list[dict[str, Any]] = Field(default_factory=list)
    remediation_complete: bool = False

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
