"""State models for Threat Scenario Runner Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ScenarioStage(StrEnum):
    """Stages of the scenario runner workflow."""

    LOAD_SCENARIO = "load_scenario"
    SETUP_ENVIRONMENT = "setup_environment"
    EXECUTE_STEPS = "execute_steps"
    EVALUATE_CONTROLS = "evaluate_controls"
    GENERATE_VERDICT = "generate_verdict"
    REPORT = "report"


class ScenarioCategory(StrEnum):
    """Categories of threat scenarios."""

    RANSOMWARE_READINESS = "ransomware_readiness"
    INSIDER_THREAT = "insider_threat"
    CLOUD_BREACH = "cloud_breach"
    SUPPLY_CHAIN = "supply_chain"
    CREDENTIAL_THEFT = "credential_theft"
    DATA_EXFIL = "data_exfil"
    PHISHING_CHAIN = "phishing_chain"
    ZERO_DAY = "zero_day"


class Verdict(StrEnum):
    """Verdict for a scenario run."""

    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    PARTIAL = "partial"
    INCONCLUSIVE = "inconclusive"


class ThreatScenario(BaseModel):
    """Definition of a threat scenario."""

    id: str = ""
    name: str = ""
    category: ScenarioCategory = ScenarioCategory.RANSOMWARE_READINESS
    description: str = ""
    steps: list[str] = Field(default_factory=list)
    expected_controls: list[str] = Field(default_factory=list)
    severity: str = "high"
    mitre_techniques: list[str] = Field(default_factory=list)


class EnvironmentSetup(BaseModel):
    """Setup state for scenario execution."""

    id: str = ""
    scenario_id: str = ""
    environment: str = ""
    prerequisites_met: bool = False
    isolation_verified: bool = False
    rollback_ready: bool = False
    setup_notes: list[str] = Field(default_factory=list)


class ScenarioStep(BaseModel):
    """Result of executing a single scenario step."""

    id: str = ""
    step_number: int = 0
    description: str = ""
    action: str = ""
    expected_outcome: str = ""
    actual_outcome: str = ""
    passed: bool = False
    evidence: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0


class ControlEvaluation(BaseModel):
    """Evaluation of a specific security control."""

    id: str = ""
    control_name: str = ""
    control_type: str = ""
    expected_behavior: str = ""
    actual_behavior: str = ""
    effective: bool = False
    confidence: float = 0.0
    notes: str = ""


class ScenarioVerdict(BaseModel):
    """Final verdict for the scenario."""

    id: str = ""
    scenario_id: str = ""
    verdict: Verdict = Verdict.INCONCLUSIVE
    score: float = 0.0
    controls_tested: int = 0
    controls_passed: int = 0
    controls_failed: int = 0
    summary: str = ""
    remediation_items: list[str] = Field(default_factory=list)


class ThreatScenarioRunnerState(BaseModel):
    """Full state of a threat scenario run."""

    # Identity
    request_id: str = ""
    stage: ScenarioStage = ScenarioStage.LOAD_SCENARIO
    tenant_id: str = ""

    # Data
    scenario: ThreatScenario = Field(default_factory=ThreatScenario)
    setup: EnvironmentSetup = Field(default_factory=EnvironmentSetup)
    steps_executed: list[ScenarioStep] = Field(default_factory=list)
    evaluations: list[ControlEvaluation] = Field(default_factory=list)
    verdict: ScenarioVerdict = Field(default_factory=ScenarioVerdict)

    # Metrics
    controls_passed: int = 0
    controls_failed: int = 0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Tracking
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
