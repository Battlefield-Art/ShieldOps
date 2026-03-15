"""Detection Engineering Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DetectionStage(StrEnum):
    ASSESS_COVERAGE = "assess_coverage"
    CREATE_RULES = "create_rules"
    TEST_RULES = "test_rules"
    TUNE = "tune"
    DEPLOY = "deploy"


class RuleType(StrEnum):
    CORRELATION = "correlation"
    THRESHOLD = "threshold"
    ANOMALY = "anomaly"
    SEQUENCE = "sequence"
    ML_BASED = "ml_based"


class RuleStatus(StrEnum):
    DRAFT = "draft"
    TESTING = "testing"
    ACTIVE = "active"
    TUNING = "tuning"
    RETIRED = "retired"


class DetectionRule(BaseModel):
    """A detection rule targeting a specific MITRE ATT&CK technique."""

    rule_id: str = ""
    name: str = ""
    rule_type: RuleType = RuleType.CORRELATION
    mitre_tactic: str = ""
    mitre_technique: str = ""
    query: str = ""
    risk_score: int = 0
    false_positive_rate: float = 0.0
    status: RuleStatus = RuleStatus.DRAFT


class CoverageGap(BaseModel):
    """A gap in MITRE ATT&CK detection coverage."""

    mitre_tactic: str = ""
    mitre_technique: str = ""
    current_coverage: float = 0.0
    priority: str = "medium"
    suggested_rule_type: RuleType = RuleType.CORRELATION


class TuningResult(BaseModel):
    """Result of tuning a detection rule to reduce false positives."""

    rule_id: str = ""
    original_fp_rate: float = 0.0
    tuned_fp_rate: float = 0.0
    tuning_action: str = ""
    detection_rate_impact: float = 0.0


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionEngineeringState(BaseModel):
    """Main state for the Detection Engineering agent graph."""

    request_id: str = ""
    stage: DetectionStage = DetectionStage.ASSESS_COVERAGE

    # Coverage assessment
    coverage_gaps: list[CoverageGap] = Field(default_factory=list)

    # Rule creation
    rules_created: list[DetectionRule] = Field(default_factory=list)

    # Testing
    test_results: list[dict[str, Any]] = Field(default_factory=list)

    # Tuning
    tuning_results: list[TuningResult] = Field(default_factory=list)

    # Deployment
    rules_deployed: list[str] = Field(default_factory=list)

    # Overall metrics
    overall_coverage: float = 0.0

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)

    # Error
    error: str = ""
