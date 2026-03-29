"""NIST Framework Mapper Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class NISTStage(StrEnum):
    MAP_FUNCTIONS = "map_functions"
    ASSESS_CATEGORIES = "assess_categories"
    SCORE_MATURITY = "score_maturity"
    IDENTIFY_GAPS = "identify_gaps"
    RECOMMEND = "recommend"
    REPORT = "report"


class CSFFunction(StrEnum):
    IDENTIFY = "identify"
    PROTECT = "protect"
    DETECT = "detect"
    RESPOND = "respond"
    RECOVER = "recover"
    GOVERN = "govern"


class TierLevel(StrEnum):
    PARTIAL = "partial"
    RISK_INFORMED = "risk_informed"
    REPEATABLE = "repeatable"
    ADAPTIVE = "adaptive"


class FunctionAssessment(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class MaturityScore(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class GapAnalysis(BaseModel):
    id: str = ""
    name: str = ""
    status: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class NISTFrameworkMapperState(BaseModel):
    request_id: str = ""
    stage: NISTStage = NISTStage.MAP_FUNCTIONS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
