"""State models for the Dark Web Intelligence Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DarkWebStage(StrEnum):
    """Stages of the dark web monitoring workflow."""

    MONITOR_FORUMS = "monitor_forums"
    COLLECT_MENTIONS = "collect_mentions"
    ANALYZE_THREATS = "analyze_threats"
    ASSESS_CREDIBILITY = "assess_credibility"
    ALERT = "alert"
    REPORT = "report"


class CredibilityLevel(StrEnum):
    """Source credibility levels."""

    VERIFIED = "verified"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"
    DISINFORMATION = "disinformation"


class ThreatCategory(StrEnum):
    """Dark web threat categories."""

    DATA_BREACH = "data_breach"
    CREDENTIAL_LEAK = "credential_leak"
    RANSOMWARE = "ransomware"
    EXPLOIT_SALE = "exploit_sale"
    INSIDER_THREAT = "insider_threat"
    BRAND_ABUSE = "brand_abuse"


class ForumSource(BaseModel):
    """A monitored dark web forum or marketplace."""

    id: str = ""
    name: str = ""
    platform_type: str = ""
    language: str = "en"
    active: bool = True
    last_scraped: str = ""


class Mention(BaseModel):
    """A mention of the organization on the dark web."""

    id: str = ""
    source_id: str = ""
    content_snippet: str = ""
    category: ThreatCategory = ThreatCategory.DATA_BREACH
    credibility: CredibilityLevel = CredibilityLevel.UNVERIFIED
    threat_actor: str = ""
    timestamp: str = ""


class ThreatAssessment(BaseModel):
    """Assessment of a dark web threat."""

    id: str = ""
    mention_id: str = ""
    severity: str = "medium"
    impact_description: str = ""
    recommended_action: str = ""
    confidence: float = 0.0


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: int = 0
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class DarkWebIntelligenceState(BaseModel):
    """Full state of a dark web intelligence workflow."""

    # Identity
    request_id: str = ""
    stage: DarkWebStage = DarkWebStage.MONITOR_FORUMS
    tenant_id: str = ""

    # Data
    forum_sources: list[dict[str, Any]] = Field(default_factory=list)
    mentions: list[dict[str, Any]] = Field(default_factory=list)
    threat_analyses: list[dict[str, Any]] = Field(default_factory=list)
    credibility_assessments: list[dict[str, Any]] = Field(default_factory=list)
    alerts_sent: list[dict[str, Any]] = Field(default_factory=list)

    # Metrics
    total_mentions: int = 0
    critical_threats: int = 0
    alerts_generated: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Tracking
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
