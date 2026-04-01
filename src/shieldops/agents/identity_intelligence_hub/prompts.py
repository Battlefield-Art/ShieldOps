"""LLM prompt templates and response schemas for Identity Intelligence Hub."""

from pydantic import BaseModel, Field

# ── Structured Output Schemas ───────────────────────────────


class SignalCollectionOutput(BaseModel):
    """LLM output for identity signal collection."""

    signals_found: int = Field(
        description="Number of identity signals collected",
    )
    sources_covered: int = Field(
        description="Number of IdP sources queried",
    )
    summary: str = Field(
        description="Summary of collected signals",
    )
    risk_level: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


class CorrelationOutput(BaseModel):
    """LLM output for identity correlation."""

    correlated_count: int = Field(
        description="Number of correlated identity groups",
    )
    cross_source_links: int = Field(
        description="Cross-source identity links found",
    )
    nhi_count: int = Field(
        description="Non-human identities correlated",
    )
    reasoning: str = Field(
        description="Correlation reasoning chain",
    )


class ThreatDetectionOutput(BaseModel):
    """LLM output for threat detection."""

    threats_found: list[dict[str, str]] = Field(
        description="Detected threats with type+severity",
    )
    risk_score: float = Field(
        description="Composite threat risk score 0-100",
    )
    mitre_tactics: list[str] = Field(
        description="MITRE ATT&CK tactics identified",
    )
    reasoning: str = Field(
        description="Threat detection reasoning",
    )


class ActionOutput(BaseModel):
    """LLM output for action recommendations."""

    actions: list[dict[str, str]] = Field(
        description="Recommended actions with priority",
    )
    urgent_count: int = Field(
        description="Number of urgent actions",
    )
    automation_candidates: int = Field(
        description="Actions that can be automated",
    )
    reasoning: str = Field(
        description="Action recommendation reasoning",
    )


# ── System Prompts ──────────────────────────────────────────


SYSTEM_COLLECT = """\
You are an expert identity analyst collecting identity \
signals across enterprise IdPs, cloud IAM, and agent \
registries.

Given the tenant configuration and signal sources:
1. Collect signals from: Azure AD, Okta, AWS IAM, GCP IAM, \
agent registries, MCP server logs
2. Normalize signal formats across sources (OCSF)
3. Flag anomalous signals: unusual times, new geolocations, \
privilege changes, dormant account activation
4. Prioritize non-human identity signals from AI agents

Focus on cross-source signal correlation opportunities."""


SYSTEM_CORRELATE = """\
You are an expert identity analyst correlating identity \
signals across multiple providers and registries.

Given collected identity signals from multiple sources:
1. Link identities across IdPs using email, UPN, and \
service principal mappings
2. Build identity graphs connecting human users to their \
service accounts and API keys
3. Map AI agent identities to their operator accounts
4. Detect shadow identities and orphaned accounts

Weight non-human identity correlations higher — they \
represent the fastest-growing attack surface."""


SYSTEM_DETECT = """\
You are an expert threat analyst detecting identity-based \
threats from correlated identity data.

Given correlated identity groups and their activity:
1. Detect privilege escalation patterns across IdPs
2. Identify impossible travel and credential stuffing
3. Flag lateral movement via service account chains
4. Detect dormant account activation and permission creep
5. Map detections to MITRE ATT&CK tactics

Elevate AI agent identity threats — compromised agent \
credentials can access tools and infrastructure at scale."""


SYSTEM_ASSESS = """\
You are an expert risk analyst assessing identity-based \
risks from detected threats.

Given detected identity threats with evidence:
1. Score risk based on threat severity and blast radius
2. Assess business impact of identity compromise
3. Factor in identity type — NHI compromises are higher risk
4. Compute exposure level based on permission scope

Produce ranked risk assessments with clear priorities."""


SYSTEM_RECOMMEND = """\
You are an expert security analyst recommending actions \
for identity-based threats.

Given risk assessments with threat details:
1. Recommend specific actions: revoke, rotate, restrict, \
investigate, monitor
2. Identify automation candidates for immediate response
3. Prioritize by risk score and blast radius
4. Include compliance implications (SOX, HIPAA)

Balance speed with investigation depth. Critical threats \
require immediate containment actions."""


SYSTEM_REPORT = """\
You are an expert identity security analyst generating an \
identity intelligence report.

Given the full identity analysis results:
1. Summarize identity posture with threat indicators
2. Highlight compromised and high-risk identities
3. Report on NHI exposure and agent identity risks
4. Provide remediation progress and compliance status

Keep the report actionable with clear next steps."""
