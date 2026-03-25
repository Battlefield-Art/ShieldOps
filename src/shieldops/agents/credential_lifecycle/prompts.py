"""Credential Lifecycle Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field

# --- Output schemas for LLM structured calls ---


class PostureAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted credential posture analysis."""

    summary: str = Field(description="Brief summary of credential posture analysis")
    critical_credentials: list[str] = Field(
        description="Credential names/IDs that require immediate attention"
    )
    risk_level: str = Field(description="Overall risk level: critical/high/medium/low/none")
    posture_recommendations: list[str] = Field(
        description="Recommendations to improve credential posture"
    )


class RotationPlanOutput(BaseModel):
    """Structured output from LLM-assisted rotation planning."""

    summary: str = Field(description="Brief summary of rotation plan")
    rotation_priority: list[str] = Field(description="Credentials ordered by rotation urgency")
    rotation_strategy: list[str] = Field(
        description="Recommended rotation strategies per credential type"
    )
    downtime_risks: list[str] = Field(description="Potential downtime risks during rotation")


class JITRecommendationOutput(BaseModel):
    """Structured output from LLM-assisted JIT credential recommendation."""

    summary: str = Field(description="Brief summary of JIT credential recommendations")
    jit_candidates: list[str] = Field(
        description="Credentials that should be replaced with JIT issuance"
    )
    scope_reductions: list[str] = Field(
        description="Scope reduction recommendations for overprivileged credentials"
    )
    ttl_recommendations: list[str] = Field(
        description="Recommended TTL values for each credential type"
    )


class RevocationOutput(BaseModel):
    """Structured output from LLM-assisted revocation analysis."""

    summary: str = Field(description="Brief summary of revocation analysis")
    revocation_targets: list[str] = Field(
        description="Credentials that should be immediately revoked"
    )
    impact_assessment: list[str] = Field(description="Impact assessment for each revocation")
    mitigation_steps: list[str] = Field(description="Steps to mitigate disruption from revocations")


# --- System prompts ---


SYSTEM_POSTURE_ANALYSIS = (
    "You are a credential security analyst specializing in posture assessment.\n"
    "Analyze the discovered credentials and their posture assessments:\n"
    "1. Identify credentials with critical risk scores or policy violations\n"
    "2. Flag overprivileged credentials with excessive scope\n"
    "3. Detect stale credentials that have not been used or rotated\n"
    "4. Evaluate compliance with rotation policies per credential type\n"
    "5. Recommend least-privilege scope reductions and rotation schedules\n"
    "Prioritize findings by risk impact and provide actionable recommendations."
)

SYSTEM_ROTATION_PLANNING = (
    "You are a credential rotation specialist planning safe credential rotations.\n"
    "Given the stale and non-compliant credentials:\n"
    "1. Prioritize rotations by risk score and policy violation severity\n"
    "2. Identify dependencies that may break during rotation\n"
    "3. Recommend rotation strategies (in-place, blue-green, gradual rollout)\n"
    "4. Estimate downtime risk for each rotation\n"
    "5. Plan rollback procedures in case rotation causes service disruption\n"
    "Ensure zero-downtime rotation where possible."
)

SYSTEM_JIT_RECOMMENDATION = (
    "You are a zero-trust credential architect recommending JIT credential issuance.\n"
    "Based on the credential posture assessment:\n"
    "1. Identify long-lived credentials that should be replaced with JIT tokens\n"
    "2. Recommend minimum-necessary scopes for each JIT credential\n"
    "3. Suggest appropriate TTL values based on usage patterns\n"
    "4. Design vault integration paths for secure credential storage\n"
    "5. Plan migration from static to JIT credentials without disruption\n"
    "Apply least-privilege and just-in-time access principles throughout."
)

SYSTEM_REVOCATION_ANALYSIS = (
    "You are a credential revocation specialist analyzing credentials for revocation.\n"
    "Evaluate the stale and compromised credentials:\n"
    "1. Confirm which credentials are safe to revoke immediately\n"
    "2. Assess blast radius of each revocation on dependent services\n"
    "3. Identify credentials that need replacement before revocation\n"
    "4. Plan notification and coordination with credential owners\n"
    "5. Document audit trail for compliance and governance\n"
    "Minimize service disruption while eliminating security risk."
)
