"""State models for the Security Automation Pipeline Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ----------------------------------------------------------


class SAPStage(StrEnum):
    """Workflow stages for security automation pipeline."""

    SCAN_PIPELINE = "scan_pipeline"
    INJECT_GATES = "inject_gates"
    RUN_CHECKS = "run_checks"
    EVALUATE_RESULTS = "evaluate_results"
    ENFORCE_GATES = "enforce_gates"
    REPORT = "report"


class GateType(StrEnum):
    """Types of security gates in CI/CD pipelines."""

    SAST = "sast"
    DAST = "dast"
    SCA = "sca"
    SECRET_SCAN = "secret_scan"
    CONTAINER_SCAN = "container_scan"
    IAC_SCAN = "iac_scan"
    LICENSE_CHECK = "license_check"


class GateStatus(StrEnum):
    """Status of a security gate."""

    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"
    PENDING = "pending"


# -- Domain Models -----------------------------------------------------


class PipelineScan(BaseModel):
    """Result of scanning a CI/CD pipeline configuration."""

    pipeline_id: str = ""
    pipeline_name: str = ""
    provider: str = ""
    branch: str = ""
    existing_gates: list[str] = Field(default_factory=list)
    missing_gates: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityGate(BaseModel):
    """A security gate injected into a pipeline."""

    gate_id: str = ""
    pipeline_id: str = ""
    gate_type: GateType = GateType.SAST
    stage: str = ""
    blocking: bool = True
    threshold: str = ""
    config: dict[str, Any] = Field(default_factory=dict)


class CheckResult(BaseModel):
    """Result of running a security check."""

    check_id: str = ""
    gate_id: str = ""
    gate_type: GateType = GateType.SAST
    status: GateStatus = GateStatus.PENDING
    findings_count: int = 0
    critical_count: int = 0
    duration_ms: int = 0
    details: dict[str, Any] = Field(default_factory=dict)


class GateEvaluation(BaseModel):
    """Evaluation of security gate results."""

    gate_id: str = ""
    passed: bool = True
    reason: str = ""
    override_allowed: bool = False
    risk_accepted: bool = False


class EnforcementAction(BaseModel):
    """An enforcement action taken on a pipeline."""

    action_id: str = ""
    pipeline_id: str = ""
    action_type: str = ""
    blocked: bool = False
    reason: str = ""
    override_by: str = ""


# -- Reasoning + State -------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the pipeline workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecurityAutomationPipelineState(BaseModel):
    """Full state for the Security Automation Pipeline workflow."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: SAPStage = SAPStage.SCAN_PIPELINE
    config: dict[str, Any] = Field(default_factory=dict)

    # Scanning
    pipeline_scans: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    pipelines_scanned: int = 0

    # Gate injection
    security_gates: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    gates_injected: int = 0

    # Checks
    check_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_findings: int = 0

    # Evaluation
    gate_evaluations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    gates_passed: int = 0
    gates_failed: int = 0

    # Enforcement
    enforcement_actions: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Report
    report: dict[str, Any] = Field(default_factory=dict)

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
