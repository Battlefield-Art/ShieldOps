"""LLM prompt templates and response schemas for the OAuth Grant Analyzer Agent."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# --- Response schemas ---


class GrantRiskOutput(BaseModel):
    """Structured output from LLM grant risk assessment."""

    high_risk_grant_ids: list[str] = Field(description="IDs of grants with elevated risk")
    risk_summary: str = Field(description="Executive summary of OAuth grant risk posture")
    risk_factors: list[str] = Field(description="Top risk factors across all discovered grants")
    overprivileged_grants: list[dict[str, Any]] = Field(
        description="Grants with more permissions than required"
    )
    risk_scores: list[dict[str, Any]] = Field(description="Per-grant risk scores with reasoning")


class PermissionOutput(BaseModel):
    """Structured output from LLM permission classification."""

    classifications: list[dict[str, Any]] = Field(
        description="Permission classifications with justification"
    )
    summary: str = Field(description="Summary of permission posture")
    scope_reduction_opportunities: list[dict[str, Any]] = Field(
        description="Grants where scope can be safely reduced"
    )


class AnomalyOutput(BaseModel):
    """Structured output from LLM anomaly detection."""

    anomalies: list[dict[str, Any]] = Field(
        description="Detected anomalies with type, severity, description"
    )
    patterns: list[str] = Field(description="Detected behavioral patterns across grants")
    threat_assessment: str = Field(description="Overall threat assessment from anomaly analysis")


class RecommendationOutput(BaseModel):
    """Structured output from LLM recommendation generation."""

    recommendations: list[dict[str, Any]] = Field(
        description="Prioritized remediation recommendations"
    )
    summary: str = Field(description="Executive summary of recommendations")
    estimated_risk_reduction_pct: float = Field(
        description="Estimated risk reduction if all recommendations are applied"
    )
    quick_wins: list[str] = Field(description="Low-effort high-impact actions to take immediately")


# --- Prompt templates ---

SYSTEM_GRANT_RISK_ANALYSIS = """\
You are an expert OAuth security analyst performing a risk assessment \
across an organization's SaaS and cloud OAuth grants.

You are given:
- A list of discovered OAuth grants with provider, scopes, status, and usage
- Permission classification data (overprivileged, unused scopes)
- Grant metadata (age, last usage, grantee, grantor)

Your task is to:
1. Score each grant's risk (0-100) based on scope breadth, staleness, and provider
2. Identify the highest-risk grants that need immediate attention
3. Flag overprivileged grants and explain why they are excessive
4. Assess the overall OAuth risk posture of the organization

Focus on actionable findings. Rank by blast radius — a full-access grant \
to a compromised external partner is worse than a stale read-only grant."""

SYSTEM_PERMISSION_CLASSIFICATION = """\
You are an expert in OAuth 2.0 permission scoping and least-privilege analysis.

You are given:
- OAuth grants with their current scopes
- Usage patterns (last used, frequency)
- Provider-specific scope semantics

Your task is to:
1. Classify each grant as read_only, read_write, admin, delegated, or full_access
2. Identify scopes that exceed what the application actually needs
3. Recommend minimum viable scope sets for each grant
4. Flag grants with dangerous scope combinations (e.g., Directory.ReadWrite + \
Application.ReadWrite in Microsoft 365)

Be precise about which scopes to remove and which to keep."""

SYSTEM_ANOMALY_DETECTION = """\
You are an expert in identity threat detection specializing in OAuth grant abuse.

You are given:
- OAuth grants with timestamps, usage patterns, and status
- Known anomaly signals and risk classifications
- Provider and scope context

Your task is to:
1. Detect anomalous grant patterns: unusual timing, scope escalation, dormant \
reactivation
2. Identify potential consent phishing attacks (new full-access grants from \
external parties)
3. Flag impossible geography or timing patterns
4. Assess whether anomalies indicate compromise vs. legitimate admin actions

Think like an attacker: consent phishing, illicit consent grants, and shadow \
IT OAuth apps are your primary concerns."""

SYSTEM_RECOMMENDATION_GENERATION = """\
You are an expert identity security architect generating OAuth grant remediation.

You are given:
- Risk-scored OAuth grants with permission classifications
- Detected anomalies and their severity
- Current grant posture across SaaS providers

Your task is to:
1. Generate prioritized actions: revoke, scope-reduce, rotate credentials, \
flag for review
2. Identify quick wins (low-effort, high-impact remediations)
3. Estimate aggregate risk reduction if all recommendations are applied
4. Tag which recommendations are safe to auto-execute vs. require human approval

IMPORTANT:
- Never recommend revoking grants that would break production integrations \
without a rollback plan
- Prefer scope reduction over full revocation when the app is legitimately needed
- Critical/suspicious grants should always require human review before action"""
