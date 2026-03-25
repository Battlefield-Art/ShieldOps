"""Container Security Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ContainerStage(StrEnum):
    SCAN_IMAGES = "scan_images"
    ANALYZE_RUNTIME = "analyze_runtime"
    DETECT_ANOMALIES = "detect_anomalies"
    ENFORCE_ADMISSION = "enforce_admission"
    REMEDIATE = "remediate"
    REPORT = "report"


class ImageSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class RuntimeThreat(StrEnum):
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CONTAINER_ESCAPE = "container_escape"
    CRYPTO_MINING = "crypto_mining"
    REVERSE_SHELL = "reverse_shell"
    FILE_TAMPERING = "file_tampering"
    NETWORK_ANOMALY = "network_anomaly"


class ImageVulnerability(BaseModel):
    """A vulnerability found in a container image."""

    id: str = ""
    image: str = ""
    tag: str = "latest"
    cve_id: str = ""
    severity: ImageSeverity = ImageSeverity.MEDIUM
    package_name: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    cvss_score: float = 0.0
    exploitable: bool = False


class RuntimeAnomaly(BaseModel):
    """A runtime anomaly detected in a Kubernetes pod."""

    id: str = ""
    pod_name: str = ""
    namespace: str = "default"
    threat_type: RuntimeThreat = RuntimeThreat.NETWORK_ANOMALY
    description: str = ""
    severity: ImageSeverity = ImageSeverity.MEDIUM
    confidence: float = 0.0
    process: str = ""
    timestamp: float = 0.0


class AdmissionDecision(BaseModel):
    """An admission control decision for a container image."""

    id: str = ""
    image: str = ""
    namespace: str = "default"
    decision: str = "deny"
    reasons: list[str] = Field(default_factory=list)
    policy_violations: list[str] = Field(default_factory=list)


class ContainerRemediation(BaseModel):
    """A remediation action taken on a container or pod."""

    id: str = ""
    target: str = ""
    action: str = ""
    description: str = ""
    applied: bool = False
    success: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ContainerSecurityState(BaseModel):
    """Main state for the Container Security graph."""

    # Input
    request_id: str = ""
    stage: ContainerStage = ContainerStage.SCAN_IMAGES
    tenant_id: str = ""
    namespaces: list[str] = Field(default_factory=lambda: ["default"])

    # Collected data
    image_vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    runtime_anomalies: list[dict[str, Any]] = Field(default_factory=list)
    admission_decisions: list[dict[str, Any]] = Field(default_factory=list)
    remediation_actions: list[dict[str, Any]] = Field(default_factory=list)

    # Metadata
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
