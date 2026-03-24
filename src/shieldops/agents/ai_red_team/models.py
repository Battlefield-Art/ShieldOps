"""State models for the AI Red Team Agent."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AttackScenario(BaseModel):
    """A generated attack scenario."""

    scenario_id: str = ""
    name: str = ""
    description: str = ""
    mitre_technique_ids: list[str] = Field(default_factory=list)
    target_assets: list[str] = Field(default_factory=list)
    complexity: str = "moderate"
    estimated_impact: str = "medium"
    prerequisites: list[str] = Field(default_factory=list)


class ProbeResult(BaseModel):
    """Result from executing a single probe."""

    probe_id: str = ""
    technique_id: str = ""
    target: str = ""
    success: bool = False
    detection_triggered: bool = False
    detection_time_ms: int = 0
    findings: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class ExploitChain(BaseModel):
    """A chain of exploits forming an attack path."""

    chain_id: str = ""
    steps: list[str] = Field(default_factory=list)
    techniques_used: list[str] = Field(default_factory=list)
    initial_access: str = ""
    final_objective: str = ""
    success_probability: float = 0.0
    risk_level: str = "medium"


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class AIRedTeamState(BaseModel):
    """Full state of an AI Red Team engagement workflow."""

    # Input
    target_environment: str = ""
    attack_objectives: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    rules_of_engagement: dict[str, Any] = Field(default_factory=dict)

    # Execution
    attack_scenarios_generated: list[AttackScenario] = Field(default_factory=list)
    probes_executed: list[ProbeResult] = Field(default_factory=list)
    vulnerabilities_found: list[dict[str, Any]] = Field(default_factory=list)
    exploit_chains: list[ExploitChain] = Field(default_factory=list)

    # Tracking
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str | None = None
