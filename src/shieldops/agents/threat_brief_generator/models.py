"""Threat Brief Generator Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class BriefStage(StrEnum):
    COLLECT_INTEL = "collect_intel"
    ANALYZE_THREATS = "analyze_threats"
    ASSESS_RELEVANCE = "assess_relevance"
    DRAFT_BRIEF = "draft_brief"
    REVIEW = "review"
    REPORT = "report"


class AudienceType(StrEnum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    SOC_ANALYST = "soc_analyst"
    BOARD = "board"
    REGULATORY = "regulatory"
    ALL_HANDS = "all_hands"


class BriefPriority(StrEnum):
    FLASH = "flash"
    URGENT = "urgent"
    ROUTINE = "routine"
    INFORMATIONAL = "informational"


class ThreatBriefGeneratorState(BaseModel):
    request_id: str = ""
    stage: BriefStage = BriefStage.COLLECT_INTEL
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
