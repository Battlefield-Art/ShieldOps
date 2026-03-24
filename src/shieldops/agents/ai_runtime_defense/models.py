"""AI Runtime Defense Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DefenseStage(StrEnum):
    SCAN_PROMPTS = "scan_prompts"
    DETECT_EXFILTRATION = "detect_exfiltration"
    DETECT_ABUSE = "detect_abuse"
    SCAN_SUPPLY_CHAIN = "scan_supply_chain"
    GENERATE_POLICIES = "generate_policies"
    EXECUTE_RESPONSE = "execute_response"
    REPORT = "report"


class ModelProvider(StrEnum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    AZURE = "azure"
    BEDROCK = "bedrock"
    VERTEX = "vertex"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# --- Supporting models ---


class PromptInjectionFinding(BaseModel):
    """A prompt injection finding from runtime scanning."""

    id: str = ""
    injection_type: str = ""
    prompt_snippet: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    confidence: float = 0.0
    description: str = ""
    mitre_technique: str = ""


class ExfiltrationAttempt(BaseModel):
    """A detected data exfiltration attempt via LLM outputs."""

    id: str = ""
    channel: str = ""
    data_classification: str = ""
    output_snippet: str = ""
    severity: FindingSeverity = FindingSeverity.HIGH
    confidence: float = 0.0
    blocked: bool = False


class ModelAbuseIncident(BaseModel):
    """A model abuse incident (jailbreak, PII extraction, etc.)."""

    id: str = ""
    abuse_type: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.HIGH
    user_id: str = ""
    model_id: str = ""
    confidence: float = 0.0


class SupplyChainRisk(BaseModel):
    """A risk identified in the AI supply chain."""

    id: str = ""
    component: str = ""
    component_type: str = ""
    risk_level: str = ""
    description: str = ""
    remediation: str = ""


class FirewallRule(BaseModel):
    """An LLM firewall rule generated from findings."""

    id: str = ""
    action: str = ""
    scope: str = ""
    pattern: str = ""
    description: str = ""
    priority: int = 0


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


# --- Main state ---


class AIRuntimeDefenseState(BaseModel):
    """Main state for the AI Runtime Defense agent graph."""

    request_id: str = ""
    stage: DefenseStage = DefenseStage.SCAN_PROMPTS

    # Input
    app_id: str = ""
    model_provider: ModelProvider = ModelProvider.ANTHROPIC
    deployment_context: dict[str, Any] = Field(default_factory=dict)
    scan_scope: list[str] = Field(default_factory=list)

    # Detection findings
    prompt_injection_findings: list[PromptInjectionFinding] = Field(default_factory=list)
    exfiltration_attempts: list[ExfiltrationAttempt] = Field(default_factory=list)
    model_abuse_incidents: list[ModelAbuseIncident] = Field(default_factory=list)
    supply_chain_risks: list[SupplyChainRisk] = Field(default_factory=list)

    # Response
    firewall_rules_generated: list[FirewallRule] = Field(default_factory=list)
    credential_rotations: list[str] = Field(default_factory=list)
    policy_recommendations: list[str] = Field(default_factory=list)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
