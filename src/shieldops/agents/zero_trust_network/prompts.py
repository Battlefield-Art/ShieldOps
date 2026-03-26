"""Zero Trust Network Access — LLM prompt templates."""

from pydantic import BaseModel, Field


class TrustAnalysisResult(BaseModel):
    """Structured output from LLM identity trust analysis."""

    summary: str = Field(description="Brief summary of trust analysis")
    risk_level: str = Field(description="Risk level: low, medium, high, critical")
    trust_adjustments: list[str] = Field(description="Recommended trust score adjustments")
    suspicious_identities: list[str] = Field(description="Identity IDs flagged as suspicious")
    recommended_actions: list[str] = Field(description="Actions to mitigate identity risks")


class PolicyDecisionResult(BaseModel):
    """Structured output from LLM policy decision analysis."""

    summary: str = Field(description="Brief summary of policy decisions")
    deny_recommendations: list[str] = Field(description="Access requests to deny with reasons")
    challenge_recommendations: list[str] = Field(
        description="Access requests requiring MFA/challenge"
    )
    policy_gaps: list[str] = Field(description="Identified gaps in current policies")
    confidence: float = Field(description="Confidence in decisions 0.0-1.0")


class SessionRiskResult(BaseModel):
    """Structured output from LLM session risk analysis."""

    summary: str = Field(description="Brief session risk summary")
    high_risk_sessions: list[str] = Field(description="Session IDs at high risk")
    anomaly_patterns: list[str] = Field(description="Detected anomaly patterns")
    terminate_sessions: list[str] = Field(description="Sessions to terminate immediately")
    quarantine_identities: list[str] = Field(description="Identities to quarantine")


SYSTEM_TRUST_ANALYSIS = (
    "You are a zero trust security analyst specializing in"
    " identity-first access control.\n"
    "Analyze the following identity trust data spanning "
    "humans, AI agents, service accounts, and MCP clients.\n"
    "For each identity:\n"
    "1. Evaluate behavioral patterns against baselines\n"
    "2. Check credential hygiene (rotation, MFA, scope)\n"
    "3. Identify over-privileged AI agents or NHIs\n"
    "4. Detect lateral movement indicators\n"
    "5. Score composite trust: behavior + credential + "
    "history"
)

SYSTEM_POLICY_DECISION = (
    "You are a zero trust policy engine for AI-native "
    "infrastructure.\n"
    "Given identity trust scores, device postures, and "
    "access requests:\n"
    "1. Apply least-privilege principle to every identity\n"
    "2. Require step-up auth for AI agents accessing "
    "sensitive resources\n"
    "3. Enforce MCP tool-level zero trust (no God Keys)\n"
    "4. Block service accounts with stale credentials\n"
    "5. Recommend dynamic policy adjustments based on "
    "risk signals"
)

SYSTEM_SESSION_RISK = (
    "You are a session security analyst for zero trust "
    "continuous verification.\n"
    "Given active session data:\n"
    "1. Detect session hijacking indicators\n"
    "2. Identify anomalous request patterns (rate, scope)\n"
    "3. Flag AI agents deviating from expected behavior\n"
    "4. Assess MCP client session integrity\n"
    "5. Recommend session termination or quarantine when"
    " trust degrades"
)
