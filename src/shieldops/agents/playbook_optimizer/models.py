"""Playbook Optimizer Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class OptimizationStage(StrEnum):
    ANALYZE_EXECUTIONS = "analyze_executions"
    IDENTIFY_BOTTLENECKS = "identify_bottlenecks"
    SUGGEST_IMPROVEMENTS = "suggest_improvements"
    SIMULATE = "simulate"
    VALIDATE = "validate"
    REPORT = "report"


class BottleneckType(StrEnum):
    SLOW_STEP = "slow_step"
    MANUAL_STEP = "manual_step"
    FAILURE_PRONE = "failure_prone"
    REDUNDANT = "redundant"
    MISSING_AUTOMATION = "missing_automation"
    ORDERING = "ordering"


class ImprovementStatus(StrEnum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    IMPLEMENTED = "implemented"
    VALIDATED = "validated"
    REJECTED = "rejected"


class PlaybookOptimizerState(BaseModel):
    request_id: str = ""
    stage: OptimizationStage = OptimizationStage.ANALYZE_EXECUTIONS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
