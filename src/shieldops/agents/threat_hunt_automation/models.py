"""State models for the Threat Hunt Automation Agent."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class THAStage(StrEnum):
    """Stages of the threat hunt automation workflow."""

    GENERATE_HYPOTHESES = "generate_hypotheses"
    DESIGN_QUERIES = "design_queries"
    EXECUTE_HUNTS = "execute_hunts"
    ANALYZE_RESULTS = "analyze_results"
    DOCUMENT_FINDINGS = "document_findings"
    REPORT = "report"


class HuntTechnique(StrEnum):
    """Techniques used for threat hunting."""

    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    ANOMALY_DETECTION = "anomaly_detection"
    IOC_SWEEP = "ioc_sweep"
    TTP_MATCHING = "ttp_matching"
    STATISTICAL_ANALYSIS = "statistical_analysis"
    ML_BASED = "ml_based"


class HuntOutcome(StrEnum):
    """Possible outcomes of a threat hunt."""

    CONFIRMED_THREAT = "confirmed_threat"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    BENIGN = "benign"
    INCONCLUSIVE = "inconclusive"
    FALSE_POSITIVE = "false_positive"


class ThreatHuntAutomationState(BaseModel):
    """Full state for threat hunt automation workflow."""

    request_id: str = ""
    stage: THAStage = THAStage.GENERATE_HYPOTHESES
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    stats: dict[str, Any] = Field(
        default_factory=dict,
    )
    reasoning_chain: list[str] = Field(
        default_factory=list,
    )
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
