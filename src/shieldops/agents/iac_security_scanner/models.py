"""IaC Security Scanner Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IACScanStage(StrEnum):
    DISCOVER_TEMPLATES = "discover_templates"
    PARSE_RESOURCES = "parse_resources"
    SCAN_MISCONFIGS = "scan_misconfigs"
    EVALUATE_POLICIES = "evaluate_policies"
    PRIORITIZE = "prioritize"
    REPORT = "report"


class IACProvider(StrEnum):
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    KUBERNETES = "kubernetes"
    HELM = "helm"
    PULUMI = "pulumi"
    ARM = "arm"
    BICEP = "bicep"
    ANSIBLE = "ansible"


class MisconfigSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IACResource(BaseModel):
    """A resource defined in an IaC template."""

    id: str = ""
    resource_type: str = ""
    resource_name: str = ""
    provider: IACProvider = IACProvider.TERRAFORM
    file_path: str = ""
    line_number: int = 0
    properties: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    is_public: bool = False
    is_encrypted: bool = True
    has_logging: bool = True


class Misconfiguration(BaseModel):
    """A misconfiguration found in IaC."""

    id: str = ""
    resource_id: str = ""
    rule_id: str = ""
    severity: MisconfigSeverity = MisconfigSeverity.MEDIUM
    title: str = ""
    description: str = ""
    file_path: str = ""
    line_number: int = 0
    provider: IACProvider = IACProvider.TERRAFORM
    cis_benchmark: str = ""
    remediation: str = ""
    expected_value: str = ""
    actual_value: str = ""
    is_auto_fixable: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class IACScannerState(BaseModel):
    """Full state for the IaC Security Scanner agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: IACScanStage = IACScanStage.DISCOVER_TEMPLATES
    scan_targets: list[str] = Field(default_factory=list)
    discovered_templates: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_templates: int = 0
    resources: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    misconfigurations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    policy_violations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    prioritized: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    total_findings: int = 0
    critical_count: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
