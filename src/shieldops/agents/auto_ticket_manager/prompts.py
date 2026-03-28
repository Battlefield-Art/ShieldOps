"""LLM prompts and schemas for the Auto Ticket Manager Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TicketClassificationOutput(BaseModel):
    """Structured output for ticket classification."""

    priority: str = Field(description="Ticket priority: P1/P2/P3/P4")
    ticket_type: str = Field(description="bug/vulnerability/task/incident")
    target_system: str = Field(description="jira/servicenow/github_issues")
    sla_hours: int = Field(description="SLA deadline in hours")
    component: str = Field(description="Affected component or team area")
    reasoning: str = Field(description="Classification justification")


class OwnerAssignmentOutput(BaseModel):
    """Structured output for owner assignment."""

    assignee: str = Field(description="Recommended assignee")
    team: str = Field(description="Owning team")
    escalation_chain: list[str] = Field(description="Escalation path")
    reasoning: str = Field(description="Assignment justification")


class TicketReportOutput(BaseModel):
    """Structured output for ticket management report."""

    executive_summary: str = Field(description="Summary for leadership")
    tickets_created: int = Field(description="New tickets created")
    sla_compliance_pct: float = Field(description="SLA compliance percentage")
    breached_tickets: list[str] = Field(description="Tickets that breached SLA")
    recommendations: list[str] = Field(description="Process improvements")


SYSTEM_CLASSIFY = """\
You are a ticket classification engine. Given a \
security finding:

1. Determine ticket priority (P1=critical, P2=high, \
P3=medium, P4=low)
2. Classify ticket type (vulnerability, incident, task)
3. Select target ticketing system
4. Set SLA deadline based on severity
5. Identify the affected component

Map severity to SLA: critical=4h, high=24h, \
medium=72h, low=168h."""


SYSTEM_ASSIGN = """\
You are a ticket routing engine. Given a classified \
ticket with its severity and component:

1. Identify the best assignee based on expertise
2. Determine the owning team
3. Build an escalation chain
4. Consider current workload balance

Route critical findings to senior engineers. \
Ensure no single person is overloaded."""


SYSTEM_REPORT = """\
You are a security operations manager summarizing \
ticket management activity.

Given ticket creation, assignment, and SLA data:
1. Write an executive summary
2. Report SLA compliance metrics
3. Highlight any SLA breaches
4. Recommend process improvements

Focus on response time and accountability."""
