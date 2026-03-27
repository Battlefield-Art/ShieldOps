"""State models for the AI Blue Team Agent."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SecurityGap(BaseModel):
    """A gap in security defenses identified from red team findings."""

    gap_id: str = ""
    category: str = ""  # access_control, monitoring, network, endpoint
    description: str = ""
    severity: str = "medium"
    affected_assets: list[str] = Field(default_factory=list)
    red_team_technique: str = ""
    current_control: str = ""
    recommended_control: str = ""


class HardeningAction(BaseModel):
    """A specific defense hardening action to apply."""

    action_id: str = ""
    action_type: str = ""  # patch, config_change, policy_update, rule_add
    target_asset: str = ""
    description: str = ""
    priority: str = "standard"
    risk_reduction_pct: float = 0.0
    rollback_plan: str = ""
    estimated_time_minutes: int = 0


class DetectionRule(BaseModel):
    """A detection rule created to catch red team techniques."""

    rule_id: str = ""
    rule_name: str = ""
    mitre_technique_id: str = ""
    data_source: str = ""
    query: str = ""
    severity: str = "medium"
    false_positive_rate: float = 0.0
    description: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent's reasoning chain."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int
    tool_used: str | None = None


class AIBlueTeamState(BaseModel):
    """Full state of an AI Blue Team defense hardening workflow."""

    # Input
    red_team_findings: list[dict[str, Any]] = Field(default_factory=list)
    environment_context: dict[str, Any] = Field(default_factory=dict)
    hardening_scope: str = ""

    # Analysis
    gaps_identified: list[SecurityGap] = Field(default_factory=list)
    hardening_actions: list[HardeningAction] = Field(default_factory=list)
    detection_rules_created: list[DetectionRule] = Field(default_factory=list)
    policies_updated: list[dict[str, Any]] = Field(default_factory=list)

    # Validation
    validation_results: list[dict[str, Any]] = Field(default_factory=list)
    regression_tests: list[dict[str, Any]] = Field(default_factory=list)

    # Tracking
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)
    current_step: str = "init"
    session_start: datetime | None = None
    session_duration_ms: int = 0
    error: str = ""
