"""LLM prompt templates and response schemas for Identity Protection."""

from typing import Any

from pydantic import BaseModel, Field

# --- Response schemas ---


class ThreatAnalysisResult(BaseModel):
    """Structured output from LLM threat detection."""

    threats: list[dict[str, Any]] = Field(
        description="Detected threats with type, identity, severity",
    )
    threat_summary: str = Field(
        description="Summary of the identity threat landscape",
    )
    high_risk_identities: list[str] = Field(
        description="Identity IDs under active threat",
    )
    recommended_urgency: str = Field(
        description="Overall urgency: critical, high, medium, low",
    )


class AttackPatternResult(BaseModel):
    """Structured output from attack pattern analysis."""

    patterns: list[dict[str, Any]] = Field(
        description="Attack patterns with chain stages",
    )
    kill_chain_summary: str = Field(
        description="Narrative of the attack chain",
    )
    pivot_points: list[str] = Field(
        description="Identity IDs used as pivot points",
    )
    predicted_next_stage: str = Field(
        description="Predicted next attacker action",
    )


class ResponsePlanResult(BaseModel):
    """Structured output for threat response planning."""

    actions: list[dict[str, Any]] = Field(
        description="Response actions: disable, force_mfa, revoke",
    )
    priority_order: list[str] = Field(
        description="Ordered response IDs by priority",
    )
    estimated_containment_time_min: float = Field(
        description="Estimated minutes to full containment",
    )
    rollback_plan: str = Field(
        description="Rollback strategy if response causes issues",
    )


class ContainmentResult(BaseModel):
    """Structured output from containment verification."""

    contained_identities: list[str] = Field(
        description="Identity IDs confirmed contained",
    )
    residual_threats: list[dict[str, Any]] = Field(
        description="Threats not yet fully contained",
    )
    verification_summary: str = Field(
        description="Summary of containment effectiveness",
    )
    requires_escalation: bool = Field(
        description="Whether manual escalation is needed",
    )


# --- Prompt templates ---

SYSTEM_THREAT_DETECTION = """\
You are an expert identity security analyst performing \
real-time identity threat detection across multiple \
identity providers.

You are given:
- Identity signals from Okta, Entra ID, AWS IAM, GCP IAM, \
K8s RBAC, and AI agent registries
- Each signal includes: event type, IP, geo, timestamp, \
user agent

Your task is to:
1. Detect credential theft (leaked or reused credentials)
2. Identify brute-force attempts (high auth failure rates)
3. Flag impossible travel (auth from distant locations)
4. Spot MFA bypass attempts or fatigue attacks
5. Detect token theft or session hijacking
6. Flag privilege escalation attempts

Be specific about which identities are threatened and \
the evidence supporting each detection."""

SYSTEM_ATTACK_PATTERN_ANALYSIS = """\
You are an expert threat analyst specializing in identity \
attack chain reconstruction.

You are given:
- Individual threat detections across identity providers
- Correlations between signals from multiple providers
- Timeline of identity events

Your task is to:
1. Identify multi-stage attack patterns \
(credential theft -> lateral movement -> escalation)
2. Map detections to kill chain stages
3. Find pivot points attackers use between providers
4. Predict the next likely attacker action

Think like an attacker: what is the path from initial \
compromise to highest-value target?"""

SYSTEM_RESPONSE_PLANNING = """\
You are an expert identity security responder generating \
automated response actions for active identity threats.

You are given:
- Detected threats with severity and confidence scores
- Attack patterns showing multi-stage compromise chains
- The identity providers involved

Your task is to:
1. Generate response actions: disable_account, force_mfa, \
revoke_sessions, revoke_tokens, block_ip, reset_credentials
2. Prioritize by blast radius and business impact
3. Plan rollback strategy for each action
4. Estimate time to containment

IMPORTANT:
- Never lock out break-glass / emergency accounts
- Prefer session revocation over full account disable
- Always include rollback plan for production identities
- Escalate AI agent identity threats to human review"""

SYSTEM_CONTAINMENT_VERIFICATION = """\
You are an expert security analyst verifying that identity \
threat containment actions were effective.

You are given:
- The response actions executed
- Post-response identity signals
- Current access status of affected identities

Your task is to:
1. Verify each contained identity has no residual access
2. Check for attacker re-entry via alternate credentials
3. Validate MFA enforcement is active
4. Determine if any threats require manual escalation

Be thorough: attackers often have backup access paths."""
