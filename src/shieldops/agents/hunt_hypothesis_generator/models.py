"""Hunt Hypothesis Generator Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class GenerationStage(StrEnum):
    ANALYZE_INTEL = "analyze_intel"
    IDENTIFY_GAPS = "identify_gaps"
    GENERATE_HYPOTHESES = "generate_hypotheses"
    PRIORITIZE = "prioritize"
    CREATE_QUERIES = "create_queries"
    REPORT = "report"


class HypothesisType(StrEnum):
    BEHAVIORAL = "behavioral"
    INDICATOR_BASED = "indicator_based"
    TTP_BASED = "ttp_based"
    ANOMALY = "anomaly"
    INTELLIGENCE_DRIVEN = "intelligence_driven"
    SITUATIONAL = "situational"


class Priority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    EXPLORATORY = "exploratory"


class HuntHypothesisGeneratorState(BaseModel):
    request_id: str = ""
    stage: GenerationStage = GenerationStage.ANALYZE_INTEL
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
