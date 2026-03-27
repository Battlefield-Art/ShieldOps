"""State models for the Digital Twin Security Agent LangGraph workflow."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SimulationStage(StrEnum):
    """Stages of a digital twin security simulation."""

    CREATE_TWIN = "create_twin"
    CONFIGURE_ENVIRONMENT = "configure_environment"
    EXECUTE_SIMULATIONS = "execute_simulations"
    ANALYZE_RESULTS = "analyze_results"
    VALIDATE_POSTURE = "validate_posture"
    REPORT = "report"


class TwinType(StrEnum):
    """Type of digital twin being simulated."""

    INFRASTRUCTURE = "infrastructure"
    APPLICATION = "application"
    NETWORK = "network"
    IDENTITY = "identity"


class PostureVerdict(StrEnum):
    """Overall security posture verdict after simulation."""

    HARDENED = "hardened"
    ADEQUATE = "adequate"
    VULNERABLE = "vulnerable"
    CRITICAL = "critical"


class DigitalTwin(BaseModel):
    """Represents a digital twin of an infrastructure component."""

    twin_id: str = ""
    twin_type: TwinType = TwinType.INFRASTRUCTURE
    name: str = ""
    source_environment: str = ""
    components: list[dict[str, Any]] = Field(default_factory=list)
    network_topology: dict[str, Any] = Field(default_factory=dict)
    identity_mappings: list[dict[str, Any]] = Field(default_factory=list)
    security_controls: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime | None = None


class SimulationScenario(BaseModel):
    """A single attack simulation scenario to execute against the twin."""

    scenario_id: str = ""
    name: str = ""
    category: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    attack_steps: list[dict[str, Any]] = Field(default_factory=list)
    expected_controls: list[str] = Field(default_factory=list)
    severity: str = "medium"


class SimulationResult(BaseModel):
    """Result of executing a simulation scenario against the twin."""

    scenario_id: str = ""
    scenario_name: str = ""
    success: bool = False
    attack_path: list[dict[str, Any]] = Field(default_factory=list)
    controls_bypassed: list[str] = Field(default_factory=list)
    controls_effective: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    findings: list[dict[str, Any]] = Field(default_factory=list)
    duration_ms: int = 0


class PostureAssessment(BaseModel):
    """Overall security posture assessment from all simulations."""

    verdict: PostureVerdict = PostureVerdict.ADEQUATE
    overall_risk_score: float = 0.0
    total_scenarios: int = 0
    scenarios_blocked: int = 0
    scenarios_succeeded: int = 0
    critical_findings: list[dict[str, Any]] = Field(default_factory=list)
    remediation_priorities: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float = 0.0


class ReasoningStep(BaseModel):
    """Audit trail entry for the digital twin security workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class DigitalTwinSecurityState(BaseModel):
    """Full state for a digital twin security workflow run."""

    # Input
    tenant_id: str = ""
    twin_config: dict[str, Any] = Field(default_factory=dict)
    scenarios_requested: list[str] = Field(default_factory=list)

    # Twin
    digital_twin: dict[str, Any] = Field(default_factory=dict)
    environment_config: dict[str, Any] = Field(default_factory=dict)

    # Simulation
    scenarios: list[dict[str, Any]] = Field(default_factory=list)
    simulation_results: list[dict[str, Any]] = Field(default_factory=list)

    # Analysis
    analysis: dict[str, Any] = Field(default_factory=dict)
    posture_assessment: dict[str, Any] = Field(default_factory=dict)
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    verdict: str = ""
    overall_risk_score: float = 0.0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    error: str = ""
