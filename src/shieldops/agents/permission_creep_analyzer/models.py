"""Permission Creep Analyzer Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AnalysisStage(StrEnum):
    COLLECT_PERMISSIONS = "collect_permissions"
    BASELINE_ROLE = "baseline_role"
    DETECT_CREEP = "detect_creep"
    ASSESS_RISK = "assess_risk"
    RECOMMEND = "recommend"
    REPORT = "report"


class CreepType(StrEnum):
    UNUSED_PERMISSION = "unused_permission"
    EXCESSIVE_SCOPE = "excessive_scope"
    ROLE_ACCUMULATION = "role_accumulation"
    CROSS_BOUNDARY = "cross_boundary"
    TEMPORAL = "temporal"
    INHERITED = "inherited"


class SeverityLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class PermissionCreepAnalyzerState(BaseModel):
    request_id: str = ""
    stage: AnalysisStage = AnalysisStage.COLLECT_PERMISSIONS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
