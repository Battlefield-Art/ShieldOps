"""Security Architecture Reviewer Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ReviewStage(StrEnum):
    COLLECT_DESIGN = "collect_design"
    ANALYZE_COMPONENTS = "analyze_components"
    IDENTIFY_RISKS = "identify_risks"
    EVALUATE_CONTROLS = "evaluate_controls"
    RECOMMEND = "recommend"
    REPORT = "report"


class ArchitectureLayer(StrEnum):
    NETWORK = "network"
    APPLICATION = "application"
    DATA = "data"
    IDENTITY = "identity"
    INFRASTRUCTURE = "infrastructure"
    GOVERNANCE = "governance"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class SecurityArchitectureReviewerState(BaseModel):
    request_id: str = ""
    stage: ReviewStage = ReviewStage.COLLECT_DESIGN
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
