"""Attack Readiness Assessor Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ReadinessStage(StrEnum):
    """Stages of the readiness assessment pipeline."""

    SELECT_SCENARIOS = "select_scenarios"
    ASSESS_PREVENTION = "assess_prevention"
    ASSESS_DETECTION = "assess_detection"
    ASSESS_RESPONSE = "assess_response"
    CALCULATE_READINESS = "calculate_readiness"
    REPORT = "report"


class AttackScenario(StrEnum):
    """Attack scenarios to assess readiness for."""

    RANSOMWARE = "ransomware"
    APT_CAMPAIGN = "apt_campaign"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN = "supply_chain"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    CLOUD_BREACH = "cloud_breach"
    DDOS = "ddos"
    DATA_EXFILTRATION = "data_exfiltration"


class ReadinessLevel(StrEnum):
    """Readiness level for an attack scenario."""

    EXCELLENT = "excellent"
    GOOD = "good"
    ADEQUATE = "adequate"
    INSUFFICIENT = "insufficient"
    CRITICAL = "critical"


class ScenarioSelection(BaseModel):
    """A selected attack scenario for assessment."""

    scenario: AttackScenario = AttackScenario.RANSOMWARE
    relevance_score: float = 0.0
    threat_intel_basis: str = ""


class PreventionAssessment(BaseModel):
    """Assessment of prevention capabilities."""

    scenario: AttackScenario = AttackScenario.RANSOMWARE
    score: float = 0.0
    controls_in_place: list[str] = Field(
        default_factory=list,
    )
    controls_missing: list[str] = Field(
        default_factory=list,
    )
    effectiveness: str = ""


class DetectionAssessment(BaseModel):
    """Assessment of detection capabilities."""

    scenario: AttackScenario = AttackScenario.RANSOMWARE
    score: float = 0.0
    detection_rules: int = 0
    coverage_pct: float = 0.0
    mean_time_to_detect: str = ""
    gaps: list[str] = Field(default_factory=list)


class ResponseAssessment(BaseModel):
    """Assessment of response capabilities."""

    scenario: AttackScenario = AttackScenario.RANSOMWARE
    score: float = 0.0
    runbook_exists: bool = False
    mean_time_to_respond: str = ""
    automation_level: str = ""
    gaps: list[str] = Field(default_factory=list)


class ReadinessScore(BaseModel):
    """Overall readiness score for a scenario."""

    scenario: AttackScenario = AttackScenario.RANSOMWARE
    prevention_score: float = 0.0
    detection_score: float = 0.0
    response_score: float = 0.0
    overall_score: float = 0.0
    readiness: ReadinessLevel = ReadinessLevel.ADEQUATE
    top_gaps: list[str] = Field(
        default_factory=list,
    )


class AttackReadinessAssessorState(BaseModel):
    """Full state for an attack readiness assessment."""

    # Input
    tenant_id: str = ""
    request_id: str = ""
    scenarios: list[str] = Field(
        default_factory=list,
    )

    # Pipeline data
    scenarios_selected: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    prevention_scores: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    detection_scores: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    response_scores: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    readiness_scores: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    # Metrics
    overall_readiness: str = ""
    weakest_area: str = ""

    # Workflow tracking
    current_stage: str = ReadinessStage.SELECT_SCENARIOS
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    error: str = ""
