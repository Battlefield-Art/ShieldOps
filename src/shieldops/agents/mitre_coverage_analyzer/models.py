"""MITRE Coverage Analyzer Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CoverageStage(StrEnum):
    """Stages of the MITRE coverage analysis pipeline."""

    INVENTORY_DETECTIONS = "inventory_detections"
    MAP_TO_MITRE = "map_to_mitre"
    CALCULATE_COVERAGE = "calculate_coverage"
    IDENTIFY_GAPS = "identify_gaps"
    RECOMMEND_RULES = "recommend_rules"
    REPORT = "report"


class MITRETactic(StrEnum):
    """MITRE ATT&CK tactics."""

    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"


class CoverageLevel(StrEnum):
    """Detection coverage level for a technique."""

    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"


class DetectionRule(BaseModel):
    """A detection rule from SIEM/EDR."""

    id: str = ""
    name: str = ""
    source: str = ""
    query: str = ""
    severity: str = ""
    enabled: bool = True
    data_sources: list[str] = Field(default_factory=list)
    tags: dict[str, Any] = Field(default_factory=dict)


class MITREMapping(BaseModel):
    """Mapping between a detection rule and MITRE technique."""

    rule_id: str = ""
    technique_id: str = ""
    technique_name: str = ""
    tactic: MITRETactic = MITRETactic.INITIAL_ACCESS
    coverage: CoverageLevel = CoverageLevel.NONE
    confidence: float = 0.0


class CoverageMatrix(BaseModel):
    """Coverage matrix entry per tactic/technique."""

    tactic: MITRETactic = MITRETactic.INITIAL_ACCESS
    technique_id: str = ""
    technique_name: str = ""
    coverage: CoverageLevel = CoverageLevel.NONE
    rule_count: int = 0
    rule_ids: list[str] = Field(default_factory=list)


class CoverageGap(BaseModel):
    """An uncovered or partially covered MITRE technique."""

    technique_id: str = ""
    technique_name: str = ""
    tactic: MITRETactic = MITRETactic.INITIAL_ACCESS
    current_coverage: CoverageLevel = CoverageLevel.NONE
    risk_score: float = 0.0
    reason: str = ""


class RuleRecommendation(BaseModel):
    """Recommended detection rule for a coverage gap."""

    gap_technique_id: str = ""
    gap_technique_name: str = ""
    recommended_rule_name: str = ""
    recommended_query: str = ""
    data_sources_needed: list[str] = Field(default_factory=list)
    estimated_effort: str = ""
    priority: str = ""


class MITRECoverageAnalyzerState(BaseModel):
    """Full state for a MITRE coverage analysis run."""

    # Input
    tenant_id: str = ""
    request_id: str = ""

    # Pipeline data
    detections_inventoried: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    mappings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    coverage_matrix: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    gaps: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metrics
    overall_coverage_pct: float = 0.0
    tactics_covered: int = 0
    techniques_total: int = 0

    # Workflow tracking
    current_stage: str = CoverageStage.INVENTORY_DETECTIONS
    reasoning_chain: list[str] = Field(default_factory=list)
    error: str = ""
