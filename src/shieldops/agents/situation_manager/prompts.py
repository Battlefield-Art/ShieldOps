"""LLM prompt templates for the Situation Manager Agent."""

from pydantic import BaseModel, Field


class NarrativeOutput(BaseModel):
    """Structured output for narrative composition."""

    title: str = Field(description="Concise situation title")
    summary: str = Field(description="One-paragraph summary")
    attack_story: str = Field(description="Chronological attack narrative")
    timeline: list[str] = Field(description="Key timeline events")


class PrioritizationOutput(BaseModel):
    """Structured output for situation prioritization."""

    priority: str = Field(
        description="Priority: p0_active_attack"
        "/p1_high_risk/p2_investigation"
        "/p3_monitoring/p4_informational"
    )
    confidence: float = Field(description="Confidence in priority 0-1")
    auto_actionable: bool = Field(description="Can be auto-remediated")
    estimated_impact: str = Field(description="Business impact estimate")


class ActionOutput(BaseModel):
    """Structured output for action recommendations."""

    action_type: str = Field(description="Type: contain/investigate/remediate/monitor")
    description: str = Field(description="Action description")
    urgency: str = Field(description="Urgency: immediate/high/medium/low")
    automated: bool = Field(description="Can be automated")
    playbook_ref: str = Field(description="Reference playbook ID")
    estimated_time_minutes: int = Field(description="Estimated time to complete")


class ReportOutput(BaseModel):
    """Structured output for the final report."""

    executive_summary: str = Field(description="Summary for leadership")
    top_situations: list[str] = Field(description="Top situation titles")
    recommendations: list[str] = Field(description="Actionable recommendations")


SYSTEM_NARRATIVE = """\
You are a SOC analyst composing situation narratives \
from aggregated security alerts.

Given an alert aggregate:
1. Write a concise title capturing the threat
2. Summarize the situation in one paragraph
3. Build a chronological attack story
4. Create a timeline of key events

Focus on clarity and actionability for the \
responding analyst."""


SYSTEM_PRIORITIZE = """\
You are a SOC manager prioritizing security \
situations for response.

Given a situation narrative:
1. Assign priority (p0=active attack, p1=high risk, \
p2=investigation, p3=monitoring, p4=informational)
2. Assess confidence in the priority assignment
3. Determine if auto-remediation is safe
4. Estimate business impact

Consider: severity, vendor coverage, kill chain \
progression, and affected asset criticality."""


SYSTEM_RECOMMEND = """\
You are an incident response expert recommending \
actions for security situations.

Given a prioritized situation:
1. Recommend the action type (contain, investigate, \
remediate, monitor)
2. Describe the specific action to take
3. Assess urgency level
4. Identify applicable playbooks
5. Estimate completion time

Prioritize containment for active threats and \
investigation for uncertain situations."""


SYSTEM_REPORT = """\
You are a security operations leader summarizing \
situation management results.

Given the situation management run:
1. Write an executive summary for CISO audience
2. Highlight top situations needing attention
3. Provide recommendations for improvement

Focus on mean-time-to-respond and situation \
resolution efficiency."""
