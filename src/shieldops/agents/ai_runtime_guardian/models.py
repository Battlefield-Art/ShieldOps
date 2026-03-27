"""AI Runtime Guardian Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class GuardianStage(StrEnum):
    MONITOR_AI_RUNTIME = "monitor_ai_runtime"
    DETECT_PROMPT_ATTACKS = "detect_prompt_attacks"
    ANALYZE_MODEL_BEHAVIOR = "analyze_model_behavior"
    GUARD_TOOL_EXECUTION = "guard_tool_execution"
    ENFORCE_GUARDRAILS = "enforce_guardrails"
    REPORT = "report"


class AIThreatVector(StrEnum):
    PROMPT_INJECTION = "prompt_injection"
    MODEL_MANIPULATION = "model_manipulation"
    TOOL_ABUSE = "tool_abuse"
    DATA_POISONING = "data_poisoning"
    AGENT_HIJACKING = "agent_hijacking"
    OUTPUT_MANIPULATION = "output_manipulation"


class GuardrailAction(StrEnum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    ALERT = "alert"


class RuntimeMonitor(BaseModel):
    """Runtime monitoring snapshot for an AI system."""

    id: str = ""
    agent_id: str = ""
    model_name: str = ""
    invocation_count: int = 0
    avg_latency_ms: float = 0.0
    error_rate_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    token_usage: int = 0
    anomaly_score: float = Field(default=0.0, ge=0.0, le=10.0)
    status: str = "healthy"


class PromptAttackDetection(BaseModel):
    """Detected prompt attack attempt."""

    id: str = ""
    agent_id: str = ""
    threat_vector: AIThreatVector = AIThreatVector.PROMPT_INJECTION
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    payload_snippet: str = ""
    technique: str = ""
    blocked: bool = False
    severity: str = "medium"


class ModelBehaviorAnalysis(BaseModel):
    """Behavioral analysis of an AI model."""

    id: str = ""
    agent_id: str = ""
    drift_score: float = Field(default=0.0, ge=0.0, le=10.0)
    output_consistency: float = Field(default=1.0, ge=0.0, le=1.0)
    hallucination_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    safety_violations: int = 0
    behavioral_flags: list[str] = Field(default_factory=list)


class ToolExecutionGuard(BaseModel):
    """Tool execution guard result."""

    id: str = ""
    agent_id: str = ""
    tool_name: str = ""
    action_taken: GuardrailAction = GuardrailAction.ALLOW
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    reason: str = ""
    parameters_sanitized: bool = False


class GuardrailEnforcement(BaseModel):
    """Guardrail enforcement record."""

    id: str = ""
    agent_id: str = ""
    rule_name: str = ""
    action: GuardrailAction = GuardrailAction.ALLOW
    threat_vector: AIThreatVector = AIThreatVector.PROMPT_INJECTION
    details: str = ""
    policy_id: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AIRuntimeGuardianState(BaseModel):
    """Main state for the AI Runtime Guardian agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: GuardianStage = GuardianStage.MONITOR_AI_RUNTIME

    # Runtime monitors
    monitors: list[RuntimeMonitor] = Field(default_factory=list)

    # Prompt attack detections
    attacks: list[PromptAttackDetection] = Field(default_factory=list)

    # Behavior analyses
    behaviors: list[ModelBehaviorAnalysis] = Field(default_factory=list)

    # Tool execution guards
    tool_guards: list[ToolExecutionGuard] = Field(default_factory=list)

    # Guardrail enforcements
    enforcements: list[GuardrailEnforcement] = Field(default_factory=list)

    # Summary
    report: str = ""
    total_agents_monitored: int = 0
    attacks_blocked: int = 0
    guardrails_triggered: int = 0

    # Reasoning
    reasoning_chain: list[ReasoningStep] = Field(default_factory=list)

    # Error
    error: str = ""
