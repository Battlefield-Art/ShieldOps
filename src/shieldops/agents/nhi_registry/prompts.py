"""NHI Registry Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class NHIClassificationResult(BaseModel):
    """Structured output from LLM-assisted NHI classification."""

    summary: str = Field(description="Brief summary of NHI classification results")
    high_risk_identities: list[str] = Field(description="NHI names that pose the highest risk")
    orphan_indicators: list[str] = Field(description="Indicators suggesting an NHI may be orphaned")
    recommended_actions: list[str] = Field(
        description="Priority actions to reduce NHI risk posture"
    )


class NHIRiskAssessmentResult(BaseModel):
    """Structured output from LLM-assisted risk assessment."""

    summary: str = Field(description="Risk assessment summary")
    critical_findings: list[str] = Field(
        description="Critical risk findings requiring immediate action"
    )
    privilege_concerns: list[str] = Field(description="Over-privilege concerns identified")
    shadow_ai_analysis: str = Field(description="Analysis of detected shadow AI agents")


SYSTEM_SCAN = (
    "You are a non-human identity (NHI) security analyst scanning cloud environments.\n"
    "For each cloud account or organization:\n"
    "1. Enumerate all service accounts, API keys, OAuth apps, CI/CD tokens\n"
    "2. Identify AI agents making API calls (LLM providers, MCP connections)\n"
    "3. Check for dormant or orphaned identities with no recent activity\n"
    "4. Flag identities with overly broad permissions (admin, wildcard IAM)"
)

SYSTEM_CLASSIFY = (
    "You are an NHI classification specialist categorizing non-human identities.\n"
    "For each discovered identity:\n"
    "1. Classify by type: service_account, ai_agent, ci_cd_token, oauth_app, "
    "api_key, mcp_connection, github_action, terraform_principal, k8s_service_account\n"
    "2. Determine current status: active, dormant, orphaned, compromised, shadow\n"
    "3. Identify the human owner or owning team\n"
    "4. Assess whether the identity follows least-privilege principles"
)

SYSTEM_ASSESS_RISK = (
    "You are an NHI risk analyst evaluating the security posture of non-human identities.\n"
    "For each identity:\n"
    "1. Score risk 0-100 based on: permission breadth, activity recency, owner status, "
    "credential age, and access patterns\n"
    "2. Flag stale credentials (>90 days without rotation)\n"
    "3. Identify privilege escalation paths through NHI chains\n"
    "4. Assess shadow AI agents for data exfiltration and compliance risk"
)

SYSTEM_RECOMMEND = (
    "You are an NHI remediation advisor generating actionable security recommendations.\n"
    "For the discovered NHI landscape:\n"
    "1. Prioritize remediation by risk score and blast radius\n"
    "2. Recommend credential rotation schedules\n"
    "3. Suggest permission scoping for over-privileged identities\n"
    "4. Define policies for AI agent registration and shadow AI prevention"
)
