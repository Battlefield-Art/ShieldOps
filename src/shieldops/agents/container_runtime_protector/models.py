"""State models for the Container Runtime Protector Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# -- StrEnums ----------------------------------------------------------


class CRPStage(StrEnum):
    """Workflow stages for container runtime protection."""

    PROFILE_WORKLOAD = "profile_workload"
    MONITOR_RUNTIME = "monitor_runtime"
    DETECT_DRIFT = "detect_drift"
    ANALYZE_SYSCALLS = "analyze_syscalls"
    ENFORCE_POLICY = "enforce_policy"
    REPORT = "report"


class WorkloadType(StrEnum):
    """Container workload types."""

    DEPLOYMENT = "deployment"
    STATEFULSET = "statefulset"
    DAEMONSET = "daemonset"
    JOB = "job"
    CRONJOB = "cronjob"
    POD = "pod"
    SIDECAR = "sidecar"


class DriftSeverity(StrEnum):
    """Severity of container drift detection."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# -- Domain Models -----------------------------------------------------


class WorkloadProfile(BaseModel):
    """Behavioral profile for a container workload."""

    workload_id: str = ""
    workload_type: WorkloadType = WorkloadType.DEPLOYMENT
    namespace: str = ""
    image: str = ""
    image_hash: str = ""
    expected_syscalls: list[str] = Field(
        default_factory=list,
    )
    expected_network: list[str] = Field(
        default_factory=list,
    )
    expected_files: list[str] = Field(
        default_factory=list,
    )
    privileged: bool = False
    host_network: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class RuntimeEvent(BaseModel):
    """A runtime event observed in a container."""

    event_id: str = ""
    workload_id: str = ""
    event_type: str = ""
    syscall: str = ""
    process: str = ""
    file_path: str = ""
    network_dst: str = ""
    timestamp: datetime | None = None
    is_anomalous: bool = False


class DriftDetection(BaseModel):
    """Drift detection result for a container."""

    drift_id: str = ""
    workload_id: str = ""
    drift_type: str = ""
    severity: DriftSeverity = DriftSeverity.MEDIUM
    original_value: str = ""
    current_value: str = ""
    description: str = ""


class SyscallAnalysis(BaseModel):
    """Analysis of syscall patterns for a workload."""

    workload_id: str = ""
    total_syscalls: int = 0
    anomalous_syscalls: int = 0
    suspicious_processes: list[str] = Field(
        default_factory=list,
    )
    risk_score: float = 0.0
    findings: list[str] = Field(default_factory=list)


class PolicyEnforcement(BaseModel):
    """Policy enforcement action for a container."""

    enforcement_id: str = ""
    workload_id: str = ""
    policy_name: str = ""
    action: str = ""
    reason: str = ""
    blocked: bool = False
    alert_sent: bool = False


# -- Reasoning + State -------------------------------------------------


class ReasoningStep(BaseModel):
    """Audit trail entry for the protector workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class ContainerRuntimeProtectorState(BaseModel):
    """Full state for the Container Runtime Protector."""

    # Identifiers
    request_id: str = ""
    tenant_id: str = ""
    stage: CRPStage = CRPStage.PROFILE_WORKLOAD
    protection_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Profiling
    workload_profiles: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    privileged_count: int = 0

    # Runtime monitoring
    runtime_events: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    anomalous_event_count: int = 0

    # Drift detection
    drift_detections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    critical_drift_count: int = 0

    # Syscall analysis
    syscall_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    max_risk_score: float = 0.0

    # Policy enforcement
    enforcement_actions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    blocked_count: int = 0

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
