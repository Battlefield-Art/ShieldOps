"""Cloud Workload Protector Agent — Pydantic state and data models."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CWPStage(StrEnum):
    SCAN_WORKLOADS = "scan_workloads"
    DETECT_ANOMALIES = "detect_anomalies"
    ANALYZE_DRIFT = "analyze_drift"
    ASSESS_VULNERABILITIES = "assess_vulnerabilities"
    CONTAIN_THREATS = "contain_threats"
    REPORT = "report"


class WorkloadSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class WorkloadType(StrEnum):
    CONTAINER = "container"
    VM = "vm"
    SERVERLESS = "serverless"
    KUBERNETES_POD = "kubernetes_pod"
    BARE_METAL = "bare_metal"


class WorkloadInventory(BaseModel):
    """A discovered workload in the cloud environment."""

    id: str = ""
    tenant_id: str = ""
    workload_type: WorkloadType = WorkloadType.CONTAINER
    name: str = ""
    namespace: str = ""
    image: str = ""
    host: str = ""
    region: str = ""
    cloud_provider: str = ""
    running: bool = True
    privileged: bool = False
    ports: list[int] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    last_scanned: float = Field(default_factory=time.time)


class RuntimeAnomaly(BaseModel):
    """A runtime anomaly detected on a workload."""

    id: str = ""
    workload_id: str = ""
    anomaly_type: str = ""
    severity: WorkloadSeverity = WorkloadSeverity.MEDIUM
    description: str = ""
    process: str = ""
    syscall: str = ""
    container_escape: bool = False
    timestamp: float = Field(default_factory=time.time)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DriftFinding(BaseModel):
    """A file integrity or config drift finding."""

    id: str = ""
    workload_id: str = ""
    file_path: str = ""
    change_type: str = ""
    severity: WorkloadSeverity = WorkloadSeverity.MEDIUM
    expected_hash: str = ""
    actual_hash: str = ""
    description: str = ""
    timestamp: float = Field(default_factory=time.time)


class VulnerabilityFinding(BaseModel):
    """A vulnerability found in a workload image or runtime."""

    id: str = ""
    workload_id: str = ""
    cve_id: str = ""
    package_name: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    severity: WorkloadSeverity = WorkloadSeverity.MEDIUM
    cvss_score: float = 0.0
    exploitable: bool = False
    description: str = ""


class ContainmentAction(BaseModel):
    """A containment action taken against a threat."""

    id: str = ""
    workload_id: str = ""
    action_type: str = ""
    target: str = ""
    description: str = ""
    applied: bool = False
    success: bool = False
    rollback_available: bool = True
    timestamp: float = Field(default_factory=time.time)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudWorkloadProtectorState(BaseModel):
    """Main state for the Cloud Workload Protector agent."""

    request_id: str = ""
    stage: CWPStage = CWPStage.SCAN_WORKLOADS
    tenant_id: str = ""

    # Workload inventory
    workloads: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Runtime anomalies
    anomalies: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Drift findings
    drift_findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Vulnerability findings
    vulnerabilities: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Containment actions
    containment_actions: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Protection score
    protection_score: float = 0.0

    # Stats / summary
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    current_step: str = ""

    # Timing
    session_start: float = Field(
        default_factory=time.time,
    )
    session_duration_ms: float = 0.0

    # Error
    error: str = ""
