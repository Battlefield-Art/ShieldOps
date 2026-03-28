"""LLM prompt templates and response schemas for the IR Playbook Engine."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ClassifyOutput(BaseModel):
    """Structured output for incident classification."""

    incident_type: str = Field(
        description="Type: malware/ransomware/data_breach/"
        "insider/phishing/ddos/supply_chain/"
        "account_compromise"
    )
    severity: str = Field(description="Severity: critical/high/medium/low")
    confidence: float = Field(description="Confidence score 0.0-1.0")
    reasoning: str = Field(description="Explanation for classification")


class PlaybookOutput(BaseModel):
    """Structured output for playbook selection."""

    playbook_name: str = Field(description="Name of the recommended playbook")
    automation_level: str = Field(description="Level: fully_automated/semi_automated/manual")
    selection_reason: str = Field(description="Reason for selecting this playbook")
    estimated_duration_min: int = Field(description="Estimated duration in minutes")


class AdaptOutput(BaseModel):
    """Structured output for response adaptation."""

    should_adapt: bool = Field(description="Whether adaptation is needed")
    adapted_step: str = Field(description="Description of adapted step")
    reason: str = Field(description="Why adaptation is necessary")
    confidence: float = Field(description="Confidence in adaptation 0.0-1.0")


class ReportOutput(BaseModel):
    """Structured output for IR summary report."""

    executive_summary: str = Field(description="One-paragraph executive summary")
    key_actions: list[str] = Field(description="Key actions taken during response")
    containment_status: str = Field(description="Overall containment status")
    recommendations: list[str] = Field(description="Follow-up recommendations")


SYSTEM_CLASSIFY = """\
You are an expert incident response analyst \
classifying security incidents.

Given the incident indicators, determine:
1. Incident type (malware, ransomware, data_breach, \
insider, phishing, ddos, supply_chain, \
account_compromise)
2. Severity (critical, high, medium, low)
3. Confidence score (0.0-1.0)

Consider IOCs, affected systems, data sensitivity, \
and attack patterns. Be precise."""


SYSTEM_SELECT_PLAYBOOK = """\
You are an expert incident commander selecting \
the optimal response playbook.

Given the incident classification and available \
playbooks, select the best match considering:
1. Incident type alignment
2. Severity-appropriate response level
3. Available automation capabilities
4. Historical effectiveness

Recommend automation level and estimated duration."""


SYSTEM_ADAPT = """\
You are an expert incident responder evaluating \
whether the current response plan needs adaptation.

Given step execution results and current incident \
state, determine:
1. Whether the response needs to be adapted
2. What specific changes should be made
3. Why the adaptation is necessary

Only recommend adaptation when evidence clearly \
supports a change in approach."""


SYSTEM_REPORT = """\
You are an expert incident response analyst \
generating a post-response summary.

Given all response actions, containment checks, \
and adaptations, produce:
1. Concise executive summary
2. Key actions taken
3. Containment effectiveness
4. Follow-up recommendations

Be direct and actionable."""
