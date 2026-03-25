"""Cloud Posture Agent — Pydantic state and data models."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PostureStage(StrEnum):
    SCAN_CLOUD = "scan_cloud"
    ASSESS_BENCHMARKS = "assess_benchmarks"
    DETECT_MISCONFIGS = "detect_misconfigs"
    PRIORITIZE_RISKS = "prioritize_risks"
    REMEDIATE = "remediate"
    REPORT = "report"


class CloudProvider(StrEnum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    KUBERNETES = "kubernetes"
    MULTI_CLOUD = "multi_cloud"


class BenchmarkFramework(StrEnum):
    CIS_AWS = "cis_aws"
    CIS_GCP = "cis_gcp"
    CIS_AZURE = "cis_azure"
    CIS_K8S = "cis_k8s"
    NIST_800_53 = "nist_800_53"
    SOC2 = "soc2"


class SeverityLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CloudResource(BaseModel):
    """A cloud resource discovered during posture scanning."""

    id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    resource_type: str = ""
    resource_id: str = ""
    region: str = ""
    tags: dict[str, str] = Field(default_factory=dict)
    compliant: bool = True
    last_scanned: float = Field(default_factory=time.time)


class BenchmarkResult(BaseModel):
    """Result of evaluating a single CIS/NIST benchmark control."""

    id: str = ""
    framework: BenchmarkFramework = BenchmarkFramework.CIS_AWS
    control_id: str = ""
    control_name: str = ""
    resource_id: str = ""
    status: str = "pass"  # pass / fail / warn
    severity: SeverityLevel = SeverityLevel.MEDIUM
    description: str = ""
    remediation: str = ""


class Misconfiguration(BaseModel):
    """An actionable misconfiguration extracted from benchmark failures."""

    id: str = ""
    resource_id: str = ""
    provider: CloudProvider = CloudProvider.AWS
    misconfig_type: str = ""
    severity: SeverityLevel = SeverityLevel.MEDIUM
    description: str = ""
    cis_reference: str = ""
    auto_remediable: bool = False
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)


class RemediationAction(BaseModel):
    """A remediation action applied to fix a misconfiguration."""

    id: str = ""
    misconfig_id: str = ""
    action: str = ""
    target: str = ""
    description: str = ""
    applied: bool = False
    success: bool = False
    rollback_available: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CloudPostureState(BaseModel):
    """Main state for the Cloud Posture CSPM agent graph."""

    request_id: str = ""
    stage: PostureStage = PostureStage.SCAN_CLOUD
    tenant_id: str = ""
    providers: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)

    # Scan results
    cloud_resources: list[dict[str, Any]] = Field(default_factory=list)

    # Benchmark assessment
    benchmark_results: list[dict[str, Any]] = Field(default_factory=list)

    # Misconfigurations
    misconfigurations: list[dict[str, Any]] = Field(default_factory=list)

    # Remediation
    remediation_actions: list[dict[str, Any]] = Field(default_factory=list)

    # Overall posture score
    posture_score: float = 0.0

    # Stats / summary
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""

    # Timing
    session_start: float = Field(default_factory=time.time)
    session_duration_ms: float = 0.0

    # Error
    error: str = ""
