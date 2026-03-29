"""CI/CD Security Auditor Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AuditStage(StrEnum):
    MAP_PIPELINES = "map_pipelines"
    CHECK_PERMISSIONS = "check_permissions"
    SCAN_CONFIGS = "scan_configs"
    DETECT_INJECTION = "detect_injection"
    ASSESS_RISK = "assess_risk"
    REPORT = "report"


class PipelineRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class CIProvider(StrEnum):
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    CIRCLE_CI = "circle_ci"
    AZURE_DEVOPS = "azure_devops"
    BITBUCKET = "bitbucket"


class CiCdSecurityAuditorState(BaseModel):
    request_id: str = ""
    stage: AuditStage = AuditStage.MAP_PIPELINES
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
