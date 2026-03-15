"""Security Posture Manager Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class PrioritizationResult(BaseModel):
    """Structured output from LLM-assisted remediation prioritization."""

    summary: str = Field(description="Brief summary of prioritization analysis")
    top_priorities: list[str] = Field(description="Top priority gaps with justification")
    quick_wins: list[str] = Field(description="Quick wins with high impact-to-effort ratio")
    risk_assessment: str = Field(description="Overall risk assessment: low, medium, high, critical")


SYSTEM_ASSESS = (
    "You are a security posture analyst assessing organizational security domains.\n"
    "For each domain (identity, network, endpoint, cloud, data):\n"
    "1. Evaluate control effectiveness using RBA risk-based scoring methodology\n"
    "2. Identify findings from compliance checks, vulnerability scans, and threat intel\n"
    "3. Score each domain on a 0-100 scale based on control coverage and effectiveness\n"
    "4. Report the number of passing vs total controls for each domain"
)

SYSTEM_IDENTIFY_GAPS = (
    "You are analyzing security domain assessments to identify posture gaps.\n"
    "For each domain assessment:\n"
    "1. Compare current state against security frameworks (NIST, CIS, ISO 27001)\n"
    "2. Identify specific gaps where controls are missing or ineffective\n"
    "3. Assign a risk category (critical/high/medium/low/informational) to each gap\n"
    "4. Provide actionable remediation guidance with estimated effort in hours"
)

SYSTEM_PRIORITIZE = (
    "You are prioritizing security gaps for remediation using RBA methodology.\n"
    "For each gap:\n"
    "1. Calculate impact-to-effort ratio to maximize security improvement per hour\n"
    "2. Weight by risk category — critical gaps always take precedence\n"
    "3. Consider dependencies between gaps (e.g., identity fixes enable network fixes)\n"
    "4. Produce a ranked list with clear justification for prioritization order"
)

SYSTEM_REPORT = (
    "You are generating a unified security posture report for executive stakeholders.\n"
    "The report must include:\n"
    "1. Overall posture score (0-100) with trend indicator (improving/stable/declining)\n"
    "2. Per-domain scores with key findings and gap counts\n"
    "3. Top prioritized recommendations with expected impact and effort\n"
    "4. RBA-aligned risk summary highlighting highest-risk entities and domains"
)
