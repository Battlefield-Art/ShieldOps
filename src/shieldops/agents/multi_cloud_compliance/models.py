"""Multi-Cloud Compliance Agent — Pydantic state and data models."""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ComplianceStage(StrEnum):
    COLLECT_CONFIGS = "collect_configs"
    EVALUATE_BENCHMARKS = "evaluate_benchmarks"
    IDENTIFY_GAPS = "identify_gaps"
    GENERATE_REMEDIATION = "generate_remediation"
    TRACK_PROGRESS = "track_progress"
    REPORT = "report"


class ComplianceFramework(StrEnum):
    CIS_AWS = "cis_aws"
    CIS_GCP = "cis_gcp"
    CIS_AZURE = "cis_azure"
    NIST_800_53 = "nist_800_53"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"


class ComplianceStatus(StrEnum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNDER_REVIEW = "under_review"


class CloudConfig(BaseModel):
    """A cloud configuration item collected for compliance."""

    id: str = ""
    provider: str = ""
    resource_type: str = ""
    resource_id: str = ""
    region: str = ""
    config_data: dict[str, Any] = Field(default_factory=dict)
    collected_at: float = Field(default_factory=time.time)


class BenchmarkControl(BaseModel):
    """A benchmark control evaluation result."""

    id: str = ""
    framework: ComplianceFramework = ComplianceFramework.CIS_AWS
    control_id: str = ""
    control_name: str = ""
    status: ComplianceStatus = ComplianceStatus.COMPLIANT
    provider: str = ""
    resource_count: int = 0
    failing_resources: list[str] = Field(default_factory=list)
    severity: str = "medium"
    description: str = ""


class ComplianceGap(BaseModel):
    """A compliance gap identified across clouds."""

    id: str = ""
    framework: str = ""
    control_id: str = ""
    providers_affected: list[str] = Field(default_factory=list)
    gap_type: str = ""
    severity: str = "medium"
    description: str = ""
    remediation_steps: list[str] = Field(default_factory=list)
    estimated_effort_hours: float = 0.0


class RemediationTask(BaseModel):
    """A remediation task for a compliance gap."""

    id: str = ""
    gap_id: str = ""
    provider: str = ""
    task_type: str = ""
    description: str = ""
    status: str = "pending"
    priority: str = "medium"
    assignee: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class MultiCloudComplianceState(BaseModel):
    """Main state for the Multi-Cloud Compliance agent graph."""

    request_id: str = ""
    stage: ComplianceStage = ComplianceStage.COLLECT_CONFIGS
    tenant_id: str = ""
    providers: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)

    # Pipeline data
    cloud_configs: list[dict[str, Any]] = Field(default_factory=list)
    benchmark_controls: list[dict[str, Any]] = Field(default_factory=list)
    compliance_gaps: list[dict[str, Any]] = Field(default_factory=list)
    remediation_tasks: list[dict[str, Any]] = Field(default_factory=list)

    # Compliance score
    compliance_score: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""

    # Timing
    session_start: float = Field(default_factory=time.time)
    session_duration_ms: float = 0.0

    # Error
    error: str = ""
