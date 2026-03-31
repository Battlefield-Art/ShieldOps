"""LLM prompt templates and response schemas for the
Security Alert Router Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ClassificationOutput(BaseModel):
    """Structured output for alert classification."""

    category: str = Field(
        description="Alert category: malware/intrusion/data_leak/policy/anomaly",
    )
    priority: str = Field(
        description="Priority: p1_critical/p2_high/p3_medium/p4_low",
    )
    confidence: float = Field(
        description="Classification confidence 0-1",
    )
    tags: list[str] = Field(
        description="Classification tags for routing",
    )


class OwnerDeterminationOutput(BaseModel):
    """Structured output for owner determination."""

    team: str = Field(
        description="Responsible team name",
    )
    reasoning: str = Field(
        description="Reasoning for team assignment",
    )
    sla_minutes: int = Field(
        description="Response SLA in minutes",
    )
    escalation_path: list[str] = Field(
        description="Escalation chain if unacknowledged",
    )


class RoutingDecisionOutput(BaseModel):
    """Structured output for routing decisions."""

    destination: str = Field(
        description="Routing destination (queue/channel)",
    )
    channel: str = Field(
        description="Notification channel: slack/pagerduty/email",
    )
    auto_response: bool = Field(
        description="Whether auto-response was triggered",
    )
    summary: str = Field(
        description="Routing decision summary",
    )


class RouterReportOutput(BaseModel):
    """Structured output for the routing report."""

    executive_summary: str = Field(
        description="Summary of alert routing run",
    )
    sla_compliance: float = Field(
        description="Percentage of alerts within SLA",
    )
    recommendations: list[str] = Field(
        description="Recommendations for routing rules",
    )
    bottlenecks: list[str] = Field(
        description="Identified routing bottlenecks",
    )


# --- System prompts ---


SYSTEM_CLASSIFY = """\
You are an expert SOC analyst classifying security \
alerts for routing.

Given a raw security alert:
1. Classify the alert category (malware, intrusion, \
data leak, policy violation, anomaly, compliance)
2. Assign priority based on severity, asset criticality, \
and business impact
3. Tag with relevant metadata for routing rules
4. Assess classification confidence

Accurate classification is critical — misrouting delays \
response and increases blast radius."""


SYSTEM_OWNER = """\
You are an expert security operations coordinator \
determining alert ownership.

Given a classified alert with priority and tags:
1. Determine the responsible team based on alert type, \
affected systems, and team specialization
2. Set appropriate SLA based on priority and business \
impact
3. Define the escalation path if unacknowledged
4. Consider on-call schedules and team capacity

Route to the team best equipped to respond quickly."""


SYSTEM_ROUTE = """\
You are an expert alert routing engine making routing \
decisions for security alerts.

Given an alert with classification and owner assignment:
1. Select the optimal routing destination (queue, \
channel, ticketing system)
2. Choose notification channel (Slack, PagerDuty, \
email, SMS)
3. Determine if automated response should be triggered
4. Summarize the routing decision for audit trail

Minimize noise while ensuring critical alerts reach \
responders immediately."""


SYSTEM_REPORT = """\
You are an expert security operations reporter \
summarizing alert routing performance.

Given the full routing run (alerts, classifications, \
routing, acknowledgments):
1. Produce a summary for SOC leadership
2. Calculate SLA compliance metrics
3. Identify routing bottlenecks and delays
4. Recommend rule improvements

Write clearly for operational improvement."""
