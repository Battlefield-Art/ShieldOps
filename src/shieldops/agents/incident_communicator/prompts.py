"""LLM prompt templates and response schemas for the Incident Communicator."""

from __future__ import annotations

from pydantic import BaseModel, Field


class StakeholderOutput(BaseModel):
    """Structured output for stakeholder identification."""

    stakeholders: list[dict[str, str]] = Field(description="Identified stakeholders with roles")
    reasoning: str = Field(description="Reasoning for stakeholder selection")


class MessageOutput(BaseModel):
    """Structured output for message composition."""

    subject: str = Field(description="Message subject line")
    body: str = Field(description="Message body content")
    tone: str = Field(description="Message tone: urgent/formal/info")


class EscalationOutput(BaseModel):
    """Structured output for escalation decisions."""

    should_escalate: bool = Field(description="Whether escalation is needed")
    escalate_to: str = Field(description="Person or role to escalate to")
    reason: str = Field(description="Reason for escalation")
    channel: str = Field(description="Channel for escalation")


class ReportOutput(BaseModel):
    """Structured output for notification summary."""

    executive_summary: str = Field(description="Summary of notifications sent")
    delivery_rate: float = Field(description="Percentage of successful deliveries")
    ack_rate: float = Field(description="Percentage acknowledged")
    recommendations: list[str] = Field(description="Improvement recommendations")


SYSTEM_IDENTIFY_STAKEHOLDERS = """\
You are an expert incident communications \
coordinator identifying stakeholders.

Given the incident severity, type, and affected \
services, determine:
1. Which stakeholders must be notified
2. Their roles and notification priority
3. Appropriate channels for each

Consider regulatory requirements, SLA obligations, \
and organizational hierarchy."""


SYSTEM_COMPOSE_MESSAGE = """\
You are an expert incident communicator drafting \
notification messages.

Given the incident details and target stakeholder:
1. Write a clear, concise subject line
2. Draft an appropriate message body
3. Set the right tone for the audience

Executives need impact summaries. Technical teams \
need details. Customers need reassurance and ETAs."""


SYSTEM_ESCALATE = """\
You are an expert incident manager deciding on \
escalation for unacknowledged notifications.

Given the notification history and urgency:
1. Determine if escalation is warranted
2. Identify the right escalation target
3. Select the escalation channel
4. Explain the escalation reason

Escalate when acknowledgment SLAs are breached \
or incident severity demands it."""


SYSTEM_REPORT = """\
You are an expert communications analyst \
generating a notification summary.

Given all deliveries, acknowledgments, and \
escalations:
1. Summarize notification effectiveness
2. Calculate delivery and acknowledgment rates
3. Identify communication gaps
4. Recommend improvements

Focus on actionable insights."""
