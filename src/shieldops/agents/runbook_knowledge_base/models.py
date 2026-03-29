"""Runbook Knowledge Base Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class KBStage(StrEnum):
    INDEX_RUNBOOKS = "index_runbooks"
    EXTRACT_PATTERNS = "extract_patterns"
    BUILD_SEARCH = "build_search"
    RECOMMEND = "recommend"
    FEEDBACK = "feedback"
    REPORT = "report"


class RunbookCategory(StrEnum):
    INCIDENT_RESPONSE = "incident_response"
    REMEDIATION = "remediation"
    INVESTIGATION = "investigation"
    COMPLIANCE = "compliance"
    MAINTENANCE = "maintenance"
    EMERGENCY = "emergency"


class RecommendationQuality(StrEnum):
    EXACT_MATCH = "exact_match"
    HIGH_RELEVANCE = "high_relevance"
    MODERATE = "moderate"
    LOW = "low"
    NO_MATCH = "no_match"


class RunbookKnowledgeBaseState(BaseModel):
    request_id: str = ""
    stage: KBStage = KBStage.INDEX_RUNBOOKS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
