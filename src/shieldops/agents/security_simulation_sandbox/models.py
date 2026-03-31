"""State models for the Security Simulation Sandbox Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class SSSStage(StrEnum):
    """Stages in the security simulation sandbox lifecycle."""

    PROVISION_SANDBOX = "provision_sandbox"
    CONFIGURE_SCENARIO = "configure_scenario"
    EXECUTE_TEST = "execute_test"
    COLLECT_RESULTS = "collect_results"
    ANALYZE = "analyze"
    REPORT = "report"


class SandboxType(StrEnum):
    """Type of sandbox environment."""

    MALWARE_DETONATION = "malware_detonation"
    ATTACK_SIMULATION = "attack_simulation"
    CONFIG_TESTING = "config_testing"
    PENETRATION_TEST = "penetration_test"
    RED_TEAM = "red_team"
    COMPLIANCE_VALIDATION = "compliance_validation"


class TestOutcome(StrEnum):
    """Outcome of a sandbox test execution."""

    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"
    DETECTED = "detected"
    EVADED = "evaded"
    INCONCLUSIVE = "inconclusive"


# --- Domain models ---


class SandboxInstance(BaseModel):
    """An isolated sandbox environment instance."""

    sandbox_id: str = ""
    sandbox_type: SandboxType = SandboxType.ATTACK_SIMULATION
    environment: str = ""
    status: str = "provisioning"
    network_isolated: bool = True
    snapshot_id: str = ""
    ttl_minutes: int = 60
    created_at: datetime | None = None


class TestScenario(BaseModel):
    """A test scenario to execute in the sandbox."""

    scenario_id: str = ""
    name: str = ""
    attack_vector: str = ""
    mitre_technique: str = ""
    payload_hash: str = ""
    expected_outcome: TestOutcome = TestOutcome.DETECTED
    parameters: dict[str, Any] = Field(default_factory=dict)


class TestResult(BaseModel):
    """Result of a sandbox test execution."""

    result_id: str = ""
    scenario_id: str = ""
    outcome: TestOutcome = TestOutcome.INCONCLUSIVE
    detection_time_ms: int = 0
    artifacts_collected: int = 0
    ioc_indicators: list[str] = Field(default_factory=list)
    severity: str = "medium"
    confidence: float = 0.0


class AnalysisResult(BaseModel):
    """Analysis of collected test results."""

    analysis_id: str = ""
    detection_coverage: float = 0.0
    evasion_rate: float = 0.0
    avg_detection_time_ms: int = 0
    gaps_found: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    risk_score: float = 0.0


class SandboxMetric(BaseModel):
    """Metric from sandbox testing."""

    metric_name: str = ""
    value: float = 0.0
    unit: str = ""
    threshold: float = 0.0
    breached: bool = False


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the sandbox workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class SecuritySimulationSandboxState(BaseModel):
    """Full state for a security simulation sandbox run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: SSSStage = SSSStage.PROVISION_SANDBOX

    # Inputs
    sandbox_name: str = ""
    sandbox_type: SandboxType = SandboxType.ATTACK_SIMULATION
    scenarios: list[dict[str, Any]] = Field(default_factory=list)
    target_environment: str = ""
    isolation_level: str = "full"

    # Pipeline fields
    sandbox_instance: dict[str, Any] = Field(default_factory=dict)
    configured_scenarios: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    test_results: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    collected_artifacts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    analysis: dict[str, Any] = Field(default_factory=dict)
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    tests_passed: int = 0
    tests_failed: int = 0
    detection_coverage: float = 0.0
    total_scenarios: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
