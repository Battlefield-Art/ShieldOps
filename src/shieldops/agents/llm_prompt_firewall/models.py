"""State models for the LLM Prompt Firewall Agent."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

# --- StrEnum classifications ---


class LPFStage(StrEnum):
    """Stages in the prompt firewall lifecycle."""

    INTERCEPT_PROMPT = "intercept_prompt"
    ANALYZE_INTENT = "analyze_intent"
    DETECT_INJECTION = "detect_injection"
    CLASSIFY_RISK = "classify_risk"
    ENFORCE = "enforce"
    REPORT = "report"


class InjectionType(StrEnum):
    """Types of prompt injection attacks."""

    DIRECT_INJECTION = "direct_injection"
    INDIRECT_INJECTION = "indirect_injection"
    JAILBREAK = "jailbreak"
    PROMPT_LEAKING = "prompt_leaking"
    PAYLOAD_SPLITTING = "payload_splitting"
    ENCODING_ATTACK = "encoding_attack"


class RiskLevel(StrEnum):
    """Risk classification for intercepted prompts."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --- Domain models ---


class InterceptedPrompt(BaseModel):
    """A prompt intercepted for analysis."""

    prompt_id: str = ""
    source_agent: str = ""
    model_target: str = ""
    prompt_text: str = ""
    context_window: list[str] = Field(default_factory=list)
    timestamp: datetime | None = None
    token_count: int = 0


class IntentAnalysis(BaseModel):
    """Analysis of prompt intent and purpose."""

    intent_id: str = ""
    prompt_id: str = ""
    detected_intent: str = ""
    expected_intent: str = ""
    intent_mismatch: bool = False
    confidence: float = 0.0
    reasoning: str = ""


class InjectionDetection(BaseModel):
    """Result of injection pattern detection."""

    detection_id: str = ""
    prompt_id: str = ""
    injection_type: InjectionType = InjectionType.DIRECT_INJECTION
    pattern_matched: str = ""
    payload_excerpt: str = ""
    confidence: float = 0.0
    is_injection: bool = False


class RiskClassification(BaseModel):
    """Risk classification for an analyzed prompt."""

    classification_id: str = ""
    prompt_id: str = ""
    risk_level: RiskLevel = RiskLevel.SAFE
    risk_score: float = 0.0
    injection_detected: bool = False
    factors: list[str] = Field(default_factory=list)
    recommendation: str = ""


class FirewallAction(BaseModel):
    """Enforcement action taken by the firewall."""

    action_id: str = ""
    prompt_id: str = ""
    action_type: str = "allow"
    reason: str = ""
    sanitized_prompt: str = ""
    applied_at: datetime | None = None


# --- Workflow state ---


class ReasoningStep(BaseModel):
    """Audit trail entry for the firewall workflow."""

    step_number: int
    action: str
    input_summary: str
    output_summary: str
    duration_ms: int = 0
    tool_used: str | None = None


class LLMPromptFirewallState(BaseModel):
    """Full state for an LLM prompt firewall run."""

    # Identity
    request_id: str = ""
    tenant_id: str = ""
    stage: LPFStage = LPFStage.INTERCEPT_PROMPT

    # Inputs
    prompts: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    known_patterns: list[str] = Field(
        default_factory=list,
    )
    policy_config: dict[str, Any] = Field(
        default_factory=dict,
    )

    # Pipeline fields
    intercepted: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    intent_analyses: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    detections: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    classifications: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    actions: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    report: dict[str, Any] = Field(default_factory=dict)

    # Outcome
    total_intercepted: int = 0
    injections_detected: int = 0
    prompts_blocked: int = 0
    prompts_sanitized: int = 0

    # Workflow tracking
    session_start: datetime | None = None
    session_duration_ms: int = 0
    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    current_step: str = "init"
    error: str = ""
