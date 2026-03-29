"""Cloud Workload Protector Agent — Pydantic state and data models."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class WorkloadStage(StrEnum):
    INVENTORY_WORKLOADS = "inventory_workloads"
    MONITOR_RUNTIME = "monitor_runtime"
    DETECT_DRIFT = "detect_drift"
    SCAN_VULNERABILITIES = "scan_vulnerabilities"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class WorkloadPlatform(StrEnum):
    EC2 = "ec2"
    GCE = "gce"
    AZURE_VM = "azure_vm"
    KUBERNETES = "kubernetes"
    ECS = "ecs"


class WorkloadSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CloudWorkload(BaseModel):
    """A cloud workload instance."""

    id: str = ""
    platform: WorkloadPlatform = WorkloadPlatform.EC2
    instance_id: str = ""
    instance_type: str = ""
    region: str = ""
    os_type: str = ""
    state: str = "running"
    tags: dict[str, str] = Field(default_factory=dict)
    agent_installed: bool = False
    last_scanned: float = Field(default_factory=time.time)


class RuntimeAnomaly(BaseModel):
    """A runtime anomaly detected on a workload."""

    id: str = ""
    workload_id: str = ""
    anomaly_type: str = ""
    severity: WorkloadSeverity = WorkloadSeverity.MEDIUM
    process_name: str = ""
    description: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    mitre_technique: str = ""


class DriftFinding(BaseModel):
    """A configuration drift finding."""

    id: str = ""
    workload_id: str = ""
    drift_type: str = ""
    severity: WorkloadSeverity = WorkloadSeverity.MEDIUM
    expected_value: str = ""
    actual_value: str = ""
    description: str = ""
    auto_remediable: bool = False


class VulnerabilityFinding(BaseModel):
    """A vulnerability found on a workload."""

    id: str = ""
    workload_id: str = ""
    cve_id: str = ""
    package_name: str = ""
    severity: WorkloadSeverity = WorkloadSeverity.MEDIUM
    cvss_score: float = 0.0
    description: str = ""
    fix_available: bool = False
    fixed_version: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudWorkloadProtectorState(BaseModel):
    """Main state for the Cloud Workload Protector agent graph."""

    request_id: str = ""
    stage: WorkloadStage = WorkloadStage.INVENTORY_WORKLOADS
    tenant_id: str = ""
    platforms: list[str] = Field(default_factory=list)

    # Pipeline data
    workloads: list[dict[str, Any]] = Field(default_factory=list)
    runtime_anomalies: list[dict[str, Any]] = Field(default_factory=list)
    drift_findings: list[dict[str, Any]] = Field(default_factory=list)
    vulnerability_findings: list[dict[str, Any]] = Field(default_factory=list)

    # Risk assessment
    risk_score: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""

    # Timing
    session_start: float = Field(default_factory=time.time)
    session_duration_ms: float = 0.0

    # Error
    error: str = ""
