"""LLM prompt templates and response schemas for the
Security Ticket Automator Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class IssueDetectionOutput(BaseModel):
    """Structured output for security issue detection."""

    issues: list[dict[str, str]] = Field(
        description="Detected security issues with title, category, and priority",
    )
    affected_assets: list[str] = Field(
        description="Assets affected by detected issues",
    )
    severity_distribution: dict[str, int] = Field(
        description="Count of issues by severity level",
    )
    confidence: float = Field(
        description="Overall detection confidence 0-1",
    )


class ContextEnrichmentOutput(BaseModel):
    """Structured output for context enrichment."""

    risk_score: float = Field(
        description="Enriched risk score 0-10",
    )
    related_cves: list[str] = Field(
        description="Related CVE identifiers",
    )
    threat_context: str = Field(
        description="Threat intelligence summary",
    )
    recommended_priority: str = Field(
        description="Recommended priority: critical/high/medium/low",
    )


class OwnerAssignmentOutput(BaseModel):
    """Structured output for ticket owner assignment."""

    assignee: str = Field(
        description="Recommended assignee identifier",
    )
    team: str = Field(
        description="Owning team name",
    )
    rationale: str = Field(
        description="Reason for assignment decision",
    )
    escalation_needed: bool = Field(
        description="Whether immediate escalation is required",
    )


class TicketReportOutput(BaseModel):
    """Structured output for ticket automation report."""

    executive_summary: str = Field(
        description="Executive summary of ticket automation run",
    )
    sla_compliance_rate: float = Field(
        description="SLA compliance rate 0-100",
    )
    recommendations: list[str] = Field(
        description="Process improvement recommendations",
    )
    risk_overview: str = Field(
        description="Overall risk posture summary",
    )


# --- System prompts ---


SYSTEM_DETECT = """\
You are an expert security issue detector analyzing \
alerts and events for ticketable security issues.

Given the incoming security telemetry and alerts:
1. Identify distinct security issues requiring tickets
2. Categorize each by type (vulnerability, misconfiguration, \
incident, compliance gap)
3. Assess initial priority based on impact and urgency
4. List affected assets for scoping

Focus on actionable issues that require human follow-up \
or automated remediation tracking."""


SYSTEM_ENRICH = """\
You are an expert security analyst enriching detected \
issues with threat intelligence and asset context.

Given a detected security issue:
1. Correlate with known CVEs and threat intelligence
2. Assess risk based on asset criticality and exposure
3. Recommend priority adjustment based on enriched context
4. Identify related historical incidents

Provide precise, evidence-based enrichment that aids \
triage and prioritization."""


SYSTEM_ASSIGN = """\
You are an expert security operations coordinator \
assigning tickets to the right owners.

Given a security ticket with enriched context:
1. Identify the best team and individual assignee
2. Consider expertise, workload, and on-call rotation
3. Determine if immediate escalation is warranted
4. Provide clear rationale for the assignment

Optimize for fastest resolution while respecting \
team capacity constraints."""


SYSTEM_REPORT = """\
You are an expert security operations reporter \
summarizing ticket automation outcomes.

Given the full ticket automation run results:
1. Produce an executive summary of all created tickets
2. Highlight SLA compliance and breach patterns
3. Recommend process improvements for faster resolution
4. Summarize overall security risk posture

Write clearly for both SOC managers and security \
leadership."""
