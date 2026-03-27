"""LLM prompt templates for Remediation Orchestrator."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ClassificationLLMResult(BaseModel):
    """Structured output for finding classification."""

    routing: str = Field(
        description=("auto_remediate, create_ticket, escalate, defer, accept_risk")
    )
    priority: str = Field(description="p0, p1, p2, p3, p4")
    assigned_agent: str = Field(description="Agent to handle remediation")
    rationale: str = Field(description="Why this routing decision")
    sla_hours: int = Field(description="SLA deadline in hours")


class OrchestratorReportResult(BaseModel):
    """Structured output for the orchestrator report."""

    title: str = Field(description="Report title")
    executive_summary: str = Field(description="1-2 sentence summary")
    risk_assessment: str = Field(description="Overall risk: low, medium, high")
    sla_compliance: str = Field(description="SLA compliance summary")
    recommendations: list[str] = Field(description="Follow-up recommendations")


SYSTEM_CLASSIFY = """\
You are a security operations expert classifying and \
routing vulnerability findings. Given a finding, decide:

1. Routing: auto_remediate (trivial/simple fixes), \
create_ticket (needs human), escalate (critical/urgent), \
defer (low risk), accept_risk (known acceptable)
2. Priority: p0 (emergency), p1 (critical), p2 (high), \
p3 (medium), p4 (low)
3. Which agent should handle it
4. SLA deadline in hours

Consider severity, CVSS score, whether it is auto-\
remediable, and the affected asset criticality."""

SYSTEM_REPORT = """\
You are a security operations expert generating a \
remediation orchestration report. Summarize findings \
received, routing decisions, tickets created, agents \
dispatched, and SLA compliance.

Keep the report concise and actionable."""
