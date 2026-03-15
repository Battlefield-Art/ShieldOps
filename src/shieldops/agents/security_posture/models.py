"""Security Posture Manager Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PostureStage(StrEnum):
    ASSESS = "assess"
    SCORE = "score"
    PRIORITIZE = "prioritize"
    RECOMMEND = "recommend"


class PostureDomain(StrEnum):
    IDENTITY = "identity"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    CLOUD = "cloud"
    DATA = "data"


class RiskCategory(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class DomainAssessment(BaseModel):
    """Assessment result for a single security domain."""

    domain: PostureDomain = PostureDomain.IDENTITY
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    findings: list[str] = Field(default_factory=list)
    controls_passing: int = Field(default=0, ge=0)
    controls_total: int = Field(default=0, ge=0)


class PostureGap(BaseModel):
    """A gap between current posture and target security state."""

    domain: PostureDomain = PostureDomain.IDENTITY
    category: RiskCategory = RiskCategory.MEDIUM
    description: str = ""
    remediation: str = ""
    effort_hours: float = Field(default=0.0, ge=0.0)
    impact_score: float = Field(default=0.0, ge=0.0, le=100.0)


class PostureReport(BaseModel):
    """Unified security posture report."""

    overall_score: float = Field(default=0.0, ge=0.0, le=100.0)
    domain_scores: dict[str, float] = Field(default_factory=dict)
    gaps: list[PostureGap] = Field(default_factory=list)
    trend: str = "stable"
    recommendations: list[str] = Field(default_factory=list)


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityPostureState(BaseModel):
    """Main state for the Security Posture Manager agent graph."""

    request_id: str = ""
    stage: PostureStage = PostureStage.ASSESS

    # Assessments
    assessments: list[DomainAssessment] = Field(default_factory=list)

    # Gaps
    gaps: list[PostureGap] = Field(default_factory=list)

    # Overall posture score
    overall_score: float = 0.0

    # Final report
    report: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
