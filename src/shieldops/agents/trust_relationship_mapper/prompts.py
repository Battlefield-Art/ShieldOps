"""LLM prompt templates for the Trust Relationship Mapper Agent."""

from pydantic import BaseModel, Field


class FederationAnalysisOutput(BaseModel):
    """Structured output for federation analysis."""

    risk_score: float = Field(description="Federation risk score 0-1")
    risk_factors: list[str] = Field(description="Identified risk factors")
    recommendation: str = Field(description="Risk mitigation recommendation")


class DelegationAnalysisOutput(BaseModel):
    """Structured output for delegation chain analysis."""

    effective_permissions: list[str] = Field(description="Effective permissions at end")
    risk_score: float = Field(description="Delegation risk score 0-1")
    is_excessive: bool = Field(description="Whether delegation is excessive")
    reasoning: str = Field(description="Analysis reasoning")


class AbuseDetectionOutput(BaseModel):
    """Structured output for trust abuse detection."""

    indicator: str = Field(description="Abuse indicator type")
    severity: str = Field(description="Severity: critical/high/medium/low")
    description: str = Field(description="Abuse description")
    recommended_action: str = Field(description="Recommended remediation")


class RiskAssessmentOutput(BaseModel):
    """Structured output for trust risk assessment."""

    overall_risk: float = Field(description="Overall risk score 0-1")
    risk_factors: list[str] = Field(description="Contributing risk factors")
    recommendation: str = Field(description="Risk mitigation recommendation")
    remediation_priority: str = Field(description="Priority: critical/high/medium/low")


class TrustReportOutput(BaseModel):
    """Structured output for the final report."""

    executive_summary: str = Field(description="Summary for leadership")
    top_risks: list[str] = Field(description="Top trust risk findings")
    recommendations: list[str] = Field(description="Actionable recommendations")


SYSTEM_FEDERATION = """\
You are an identity security expert analyzing \
federation trust relationships.

Given a federation mapping between identity \
providers and service providers:
1. Assess the risk score based on protocol, \
claims, and usage patterns
2. Identify risk factors (stale tokens, \
excessive claims, no MFA)
3. Recommend mitigations

Focus on federation abuse vectors: token \
replay, claim escalation, IdP compromise."""


SYSTEM_DELEGATION = """\
You are a security analyst evaluating delegation \
chains for excessive permissions.

Given a delegation chain:
1. Calculate effective permissions at the end
2. Assess risk of transitive delegation
3. Identify excessive delegation patterns
4. Recommend least-privilege improvements

Consider: chain depth, permission escalation, \
cross-boundary delegation, AI agent delegation."""


SYSTEM_ABUSE = """\
You are a threat hunter detecting trust \
relationship abuse indicators.

Given trust boundary data:
1. Identify abuse indicators (stale federation, \
excessive delegation, cross-account pivot, \
trust chain bypass, orphaned trust)
2. Assign severity
3. Describe the abuse pattern
4. Recommend remediation

Focus on lateral movement via trust abuse and \
AI agent delegation exploitation."""


SYSTEM_RISK = """\
You are a risk analyst assessing trust \
relationship risk posture.

Given trust boundaries, federations, and abuses:
1. Calculate overall risk score (0-1)
2. List contributing risk factors
3. Recommend risk mitigation
4. Prioritize remediation

Consider: blast radius of trust compromise, \
transitive trust exploitation, and AI agent \
trust chain risks."""


SYSTEM_REPORT = """\
You are a security leader summarizing trust \
relationship mapping results.

Given the trust mapping run results:
1. Write an executive summary for CISO audience
2. Highlight top trust risk findings
3. Provide actionable recommendations

Focus on reducing trust attack surface and \
eliminating stale/excessive trust relationships."""
