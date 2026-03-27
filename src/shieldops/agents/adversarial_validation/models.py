"""State models for the Adversarial Validation Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ValidationStage(StrEnum):
    """Stages of the adversarial validation workflow."""

    COLLECT_FINDINGS = "collect_findings"
    SELECT_RETESTS = "select_retests"
    EXECUTE_VALIDATION = "execute_validation"
    ASSESS_EFFECTIVENESS = "assess_effectiveness"
    UPDATE_PATTERNS = "update_patterns"
    REPORT = "report"


class ValidationOutcome(StrEnum):
    """Outcome of a single validation test against a patched defense."""

    BLOCKED = "blocked"
    DETECTED = "detected"
    PARTIALLY_BLOCKED = "partially_blocked"
    BYPASSED = "bypassed"
    INCONCLUSIVE = "inconclusive"


class DefenseType(StrEnum):
    """Types of blue-team defenses that can be validated."""

    FIREWALL_RULE = "firewall_rule"
    POLICY_UPDATE = "policy_update"
    CREDENTIAL_ROTATION = "credential_rotation"
    CONFIG_HARDENING = "config_hardening"
    DETECTION_RULE = "detection_rule"
    ACCESS_RESTRICTION = "access_restriction"


class RedTeamFinding(BaseModel):
    """A red-team finding that has been addressed by the blue team."""

    id: str = ""
    technique_id: str = ""
    technique_name: str = ""
    target: str = ""
    severity: str = "medium"
    originally_successful: bool = True
    blue_team_fix_id: str = ""
    fix_applied_at: float = 0.0


class ValidationTest(BaseModel):
    """Result of re-running a red-team attack against a patched defense."""

    id: str = ""
    finding_id: str = ""
    technique_id: str = ""
    target: str = ""
    defense_type: DefenseType = DefenseType.DETECTION_RULE
    outcome: ValidationOutcome = ValidationOutcome.INCONCLUSIVE
    confidence: float = 0.0
    execution_time_ms: float = 0.0
    evidence: list[str] = Field(default_factory=list)


class EffectivenessScore(BaseModel):
    """Aggregated effectiveness for a single defense type."""

    id: str = ""
    defense_type: DefenseType = DefenseType.DETECTION_RULE
    tests_run: int = 0
    tests_blocked: int = 0
    effectiveness_pct: float = 0.0
    regression_detected: bool = False
    recommendations: list[str] = Field(default_factory=list)


class PatternUpdate(BaseModel):
    """A pattern update fed back into the attack/defense databases."""

    id: str = ""
    pattern_type: str = ""
    old_pattern: str = ""
    new_pattern: str = ""
    source: str = "validation"  # red_team | blue_team | validation
    applied: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: int = 0
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AdversarialValidationState(BaseModel):
    """Full state of an adversarial validation workflow."""

    # Identity
    request_id: str = ""
    stage: ValidationStage = ValidationStage.COLLECT_FINDINGS
    tenant_id: str = ""

    # Data
    red_team_findings: list[RedTeamFinding] = Field(default_factory=list)
    validation_tests: list[ValidationTest] = Field(default_factory=list)
    effectiveness_scores: list[EffectivenessScore] = Field(default_factory=list)
    pattern_updates: list[PatternUpdate] = Field(default_factory=list)

    # Metrics
    overall_effectiveness: float = 0.0
    regressions_found: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Tracking
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
