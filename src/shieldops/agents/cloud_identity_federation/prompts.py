"""Cloud Identity Federation Agent — LLM prompt templates and schemas."""

from pydantic import BaseModel, Field


class FederationAnalysisOutput(BaseModel):
    """LLM output for federation analysis."""

    summary: str = Field(description="Federation analysis summary")
    risk_level: str = Field(description="Risk: critical/high/medium/low")
    misconfig_count: int = Field(description="SSO misconfigurations found")
    recommendations: list[str] = Field(description="Remediation recommendations")


class TrustChainOutput(BaseModel):
    """LLM output for trust chain analysis."""

    summary: str = Field(description="Trust chain analysis summary")
    weak_links: list[str] = Field(description="Weakest links in trust chain")
    cross_cloud_risks: list[str] = Field(description="Cross-cloud identity risks")


class IdentityRiskOutput(BaseModel):
    """LLM output for identity risk assessment."""

    summary: str = Field(description="Identity risk assessment summary")
    risk_level: str = Field(description="Risk: critical/high/medium/low")
    priority_actions: list[str] = Field(description="Priority actions")
    compliance_impact: list[str] = Field(description="Compliance framework impact")


SYSTEM_FEDERATION_ANALYSIS = (
    "You are a cloud identity federation security analyst.\n"
    "Analyze SSO and federation configurations:\n"
    "1. Detect misconfigured SAML/OIDC assertions\n"
    "2. Identify overly permissive session durations\n"
    "3. Flag missing MFA enforcement in federation\n"
    "4. Check attribute mapping correctness"
)

SYSTEM_TRUST_CHAIN = (
    "You are a federation trust chain analyst.\n"
    "Analyze trust relationships across cloud providers:\n"
    "1. Map complete trust chains from IdP to cloud roles\n"
    "2. Identify weakest links in trust chains\n"
    "3. Detect circular or overly broad trust relationships\n"
    "4. Assess cross-cloud identity takeover risks"
)

SYSTEM_IDENTITY_RISK = (
    "You are an identity federation risk assessor.\n"
    "Assess overall federation security risk:\n"
    "1. Score risk from SSO misconfigurations\n"
    "2. Evaluate cross-cloud identity exposure\n"
    "3. Map findings to compliance frameworks\n"
    "4. Recommend prioritized remediation steps"
)
