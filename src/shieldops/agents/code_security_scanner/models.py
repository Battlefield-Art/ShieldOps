"""Code Security Scanner Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ScanStage(StrEnum):
    DISCOVER_REPOSITORIES = "discover_repositories"
    SCAN_IAC = "scan_iac"
    SCAN_DEPENDENCIES = "scan_dependencies"
    SCAN_APPLICATION_CODE = "scan_application_code"
    PRIORITIZE_FINDINGS = "prioritize_findings"
    REPORT = "report"


class ScanTarget(StrEnum):
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    KUBERNETES_YAML = "kubernetes_yaml"
    DOCKERFILE = "dockerfile"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    GO = "go"
    PROMPT_TEMPLATE = "prompt_template"
    AGENT_CONFIG = "agent_config"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Repository(BaseModel):
    """A discovered repository or code source to scan."""

    id: str = ""
    name: str = ""
    url: str = ""
    branch: str = "main"
    languages: list[str] = Field(default_factory=list)
    has_iac: bool = False
    has_ai_code: bool = False
    file_count: int = 0


class IaCScanResult(BaseModel):
    """Result from scanning Infrastructure-as-Code files."""

    id: str = ""
    repo_id: str = ""
    target_type: ScanTarget = ScanTarget.TERRAFORM
    file_path: str = ""
    line_number: int = 0
    rule_id: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    title: str = ""
    description: str = ""
    resource_type: str = ""
    remediation: str = ""
    cis_benchmark: str = ""


class DependencyScanResult(BaseModel):
    """Result from scanning dependencies for known CVEs."""

    id: str = ""
    repo_id: str = ""
    package_name: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    cve_id: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    cvss_score: float = 0.0
    description: str = ""
    is_direct: bool = True
    ecosystem: str = ""


class CodeScanResult(BaseModel):
    """Result from static analysis of application code."""

    id: str = ""
    repo_id: str = ""
    file_path: str = ""
    line_number: int = 0
    rule_id: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    category: str = ""
    title: str = ""
    description: str = ""
    snippet: str = ""
    cwe_id: str = ""
    is_ai_specific: bool = False


class PrioritizedFinding(BaseModel):
    """A finding after LLM-assisted prioritization."""

    id: str = ""
    source_finding_id: str = ""
    finding_type: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    priority_score: float = 0.0
    title: str = ""
    description: str = ""
    file_path: str = ""
    remediation: str = ""
    is_exploitable: bool = False
    is_ai_specific: bool = False
    tags: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single reasoning step in the agent chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class CodeSecurityScannerState(BaseModel):
    """Full state for the Code Security Scanner agent."""

    request_id: str = ""
    stage: ScanStage = ScanStage.DISCOVER_REPOSITORIES
    tenant_id: str = ""
    scan_targets: list[str] = Field(default_factory=list)
    repos_scanned: list[Repository] = Field(default_factory=list)
    iac_findings: list[IaCScanResult] = Field(default_factory=list)
    dependency_findings: list[DependencyScanResult] = Field(default_factory=list)
    code_findings: list[CodeScanResult] = Field(default_factory=list)
    prioritized: list[PrioritizedFinding] = Field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
