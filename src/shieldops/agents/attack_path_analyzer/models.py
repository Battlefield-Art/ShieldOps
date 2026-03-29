"""Attack Path Analyzer Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AnalyzerStage(StrEnum):
    DISCOVER_ASSETS = "discover_assets"
    MAP_RELATIONSHIPS = "map_relationships"
    IDENTIFY_PATHS = "identify_paths"
    CALCULATE_RISK = "calculate_risk"
    RECOMMEND_MITIGATIONS = "recommend_mitigations"
    REPORT = "report"


class AssetCriticality(StrEnum):
    CROWN_JEWEL = "crown_jewel"
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class PathSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AttackPathAnalyzerState(BaseModel):
    request_id: str = ""
    stage: AnalyzerStage = AnalyzerStage.DISCOVER_ASSETS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
