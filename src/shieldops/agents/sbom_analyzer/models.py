"""SBOM Analyzer Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AnalysisStage(StrEnum):
    PARSE_SBOM = "parse_sbom"
    MATCH_CVES = "match_cves"
    CHECK_LICENSES = "check_licenses"
    ASSESS_RISK = "assess_risk"
    PRIORITIZE = "prioritize"
    REPORT = "report"


class SBOMFormat(StrEnum):
    SPDX = "spdx"
    CYCLONEDX = "cyclonedx"
    SWID = "swid"
    CUSTOM = "custom"


class ComponentRisk(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class SbomAnalyzerState(BaseModel):
    request_id: str = ""
    stage: AnalysisStage = AnalysisStage.PARSE_SBOM
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
