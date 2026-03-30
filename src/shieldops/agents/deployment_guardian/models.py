"""Deployment Guardian Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DGStage(StrEnum):
    ANALYZE_CHANGES = "analyze_changes"
    RUN_PREFLIGHT = "run_preflight"
    VALIDATE_SECURITY = "validate_security"
    APPROVE_DEPLOYMENT = "approve_deployment"
    MONITOR_ROLLOUT = "monitor_rollout"
    REPORT = "report"


class DeploymentPhase(StrEnum):
    BUILD = "build"
    TEST = "test"
    STAGING = "staging"
    CANARY = "canary"
    PRODUCTION = "production"
    ROLLBACK = "rollback"


class RiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"
    APPROVED = "approved"


class DeploymentGuardianState(BaseModel):
    request_id: str = ""
    stage: DGStage = DGStage.ANALYZE_CHANGES
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
