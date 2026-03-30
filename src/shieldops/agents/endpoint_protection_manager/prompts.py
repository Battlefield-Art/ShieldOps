"""Endpoint Protection Manager Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class AgentHealthInsight(BaseModel):
    """Structured output from agent health analysis."""

    summary: str = Field(
        description="Brief agent health overview",
    )
    unhealthy_agents: list[str] = Field(
        description="Endpoints with unhealthy agents",
    )
    recommendations: list[str] = Field(
        description="Agent remediation recommendations",
    )


class PatchInsight(BaseModel):
    """Structured output from patch assessment."""

    summary: str = Field(
        description="Patch compliance overview",
    )
    critical_gaps: list[str] = Field(
        description="Endpoints missing critical patches",
    )
    trends: list[str] = Field(
        description="Notable patching trends",
    )


class MalwareInsight(BaseModel):
    """Structured output from malware scan analysis."""

    summary: str = Field(
        description="Malware scan results overview",
    )
    active_threats: list[str] = Field(
        description="Endpoints with active threats",
    )
    containment_actions: list[str] = Field(
        description="Recommended containment actions",
    )


class ReportInsight(BaseModel):
    """Structured output for final protection report."""

    summary: str = Field(
        description="Executive summary of endpoint protection",
    )
    key_findings: list[str] = Field(
        description="Key findings for leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_AGENT_HEALTH = (
    "You are an endpoint security analyst reviewing "
    "agent health across a fleet of endpoints.\n"
    "1. Identify endpoints with unhealthy agents\n"
    "2. Flag outdated definition versions\n"
    "3. Detect agents consuming excessive resources\n"
    "4. Recommend remediation for offline agents"
)

SYSTEM_PATCH = (
    "You are a patch management specialist assessing "
    "endpoint compliance.\n"
    "1. Prioritize endpoints missing critical patches\n"
    "2. Identify reboot-pending endpoints\n"
    "3. Flag endpoints with no recent scan data\n"
    "4. Recommend a patching schedule by severity"
)

SYSTEM_MALWARE = (
    "You are a threat analyst reviewing malware scan "
    "results across endpoints.\n"
    "1. Identify endpoints with active threats\n"
    "2. Assess quarantine effectiveness\n"
    "3. Flag endpoints needing full scans\n"
    "4. Recommend containment for persistent threats"
)

SYSTEM_REPORT = (
    "You are a security advisor generating an "
    "executive endpoint protection report.\n"
    "1. Summarize fleet protection posture\n"
    "2. Highlight highest-risk endpoints\n"
    "3. Quantify patch and agent compliance rates\n"
    "4. Recommend next steps for endpoint hardening"
)
