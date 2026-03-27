"""AI Runtime Guardian Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class RuntimeInsight(BaseModel):
    """Structured output from runtime monitoring."""

    summary: str = Field(description="Runtime health overview")
    anomalous_agents: list[str] = Field(description="Agents showing anomalous behavior")
    risk_indicators: list[str] = Field(description="Key risk indicators detected")


class AttackInsight(BaseModel):
    """Structured output from prompt attack detection."""

    summary: str = Field(description="Attack detection overview")
    attack_patterns: list[str] = Field(description="Patterns of detected attacks")
    mitigation_actions: list[str] = Field(description="Recommended mitigations")


class BehaviorInsight(BaseModel):
    """Structured output from behavior analysis."""

    summary: str = Field(description="Model behavior overview")
    drift_warnings: list[str] = Field(description="Models with significant drift")
    safety_concerns: list[str] = Field(description="Safety-related behavioral flags")


class GuardrailInsight(BaseModel):
    """Structured output from guardrail enforcement."""

    summary: str = Field(description="Guardrail enforcement overview")
    policy_gaps: list[str] = Field(description="Gaps in guardrail coverage")
    hardening_recs: list[str] = Field(description="Recommendations to harden guardrails")


SYSTEM_MONITOR = (
    "You are an AI runtime security analyst monitoring "
    "AI agent infrastructure.\n"
    "1. Identify agents with abnormal latency or error rates\n"
    "2. Flag anomalous token usage patterns\n"
    "3. Detect potential resource exhaustion attacks\n"
    "4. Assess overall AI runtime health"
)

SYSTEM_ATTACK = (
    "You are a prompt injection detection specialist.\n"
    "1. Classify detected prompt attacks by technique\n"
    "2. Assess attack sophistication and intent\n"
    "3. Identify attack campaign patterns\n"
    "4. Recommend immediate blocking actions"
)

SYSTEM_BEHAVIOR = (
    "You are an AI model behavior analyst.\n"
    "1. Assess model output drift from baselines\n"
    "2. Identify hallucination patterns\n"
    "3. Flag safety violation trends\n"
    "4. Recommend retraining or rollback actions"
)

SYSTEM_GUARDRAIL = (
    "You are an AI guardrail enforcement analyst.\n"
    "1. Evaluate guardrail coverage completeness\n"
    "2. Identify policy gaps in tool execution\n"
    "3. Assess quarantine effectiveness\n"
    "4. Recommend guardrail hardening measures"
)
