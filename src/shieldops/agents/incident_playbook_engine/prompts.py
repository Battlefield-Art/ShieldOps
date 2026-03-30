"""LLM prompt templates and response schemas for the Incident Playbook Engine."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ClassifyIncidentOutput(BaseModel):
    """Structured output for LLM incident classification."""

    category: str = Field(
        description=(
            "Incident category: malware/phishing/insider_threat/"
            "data_breach/ddos/ransomware/supply_chain"
        ),
    )
    severity: str = Field(
        description="Severity: critical/high/medium/low",
    )
    confidence: float = Field(
        description="Confidence score 0.0 to 1.0",
    )
    reasoning: str = Field(
        description="Explanation for the classification",
    )
    indicators: list[str] = Field(
        description="Key indicators identified in the alert",
    )


class SelectPlaybookOutput(BaseModel):
    """Structured output for LLM playbook selection."""

    playbook_name: str = Field(
        description="Name of the best-matching playbook",
    )
    match_reasoning: str = Field(
        description="Why this playbook is the best fit",
    )
    adaptation_notes: list[str] = Field(
        description="Suggested adaptations for this incident",
    )


class AdaptStepsOutput(BaseModel):
    """Structured output for LLM step adaptation."""

    adapted_steps: list[str] = Field(
        description="Ordered list of adapted step descriptions",
    )
    skipped_steps: list[str] = Field(
        description="Steps skipped and why",
    )
    added_steps: list[str] = Field(
        description="Additional steps added for this context",
    )


class ValidateOutcomeOutput(BaseModel):
    """Structured output for LLM outcome validation."""

    success: bool = Field(
        description="Whether the playbook execution succeeded",
    )
    residual_risk: str = Field(
        description="Residual risk level: none/low/medium/high",
    )
    recommendations: list[str] = Field(
        description="Follow-up recommendations",
    )
    lessons_learned: list[str] = Field(
        description="Lessons learned for playbook improvement",
    )


class ReportOutput(BaseModel):
    """Structured output for the final execution report."""

    executive_summary: str = Field(
        description="One-paragraph executive summary",
    )
    key_actions_taken: list[str] = Field(
        description="Key actions taken during execution",
    )
    risk_assessment: str = Field(
        description="Overall risk: critical/high/medium/low/none",
    )
    improvement_suggestions: list[str] = Field(
        description="Suggestions for playbook improvement",
    )


SYSTEM_CLASSIFY = """\
You are an expert incident response analyst classifying \
security incidents.

Given the alert title, description, source, severity, and \
indicators, determine:
1. Incident category (malware, phishing, insider_threat, \
data_breach, ddos, ransomware, supply_chain)
2. Severity (critical, high, medium, low)
3. Confidence in classification (0.0 to 1.0)
4. Key indicators that support the classification

Consider: attack vectors, IOCs, affected asset types, \
temporal patterns, and MITRE ATT&CK mapping. Classify \
conservatively when uncertain."""


SYSTEM_SELECT_PLAYBOOK = """\
You are an expert incident commander selecting the optimal \
response playbook.

Given the incident classification and available playbooks \
with historical success rates, determine:
1. Which playbook best matches this incident
2. Why it is the best fit given the classification
3. What adaptations are needed for this specific context

Prioritize playbooks with high historical success rates \
and low average resolution times for the given category."""


SYSTEM_ADAPT_STEPS = """\
You are an expert incident response engineer adapting \
playbook steps to a specific incident context.

Given the selected playbook steps and the incident details, \
determine:
1. Which steps should be kept, modified, or reordered
2. Which steps can be safely skipped
3. What additional steps should be added

Consider: affected asset types, blast radius, time \
sensitivity, and approval requirements. Ensure containment \
steps precede eradication steps."""


SYSTEM_VALIDATE = """\
You are an expert incident response validator assessing \
playbook execution outcomes.

Given the execution results and verification checks, \
determine:
1. Whether the incident was successfully resolved
2. Residual risk level (none, low, medium, high)
3. Follow-up recommendations
4. Lessons learned for playbook improvement

Be thorough: check for persistence mechanisms, lateral \
movement, and data exfiltration indicators."""


SYSTEM_REPORT = """\
You are an expert incident response analyst generating an \
execution summary report.

Given all playbook execution results, produce:
1. A concise executive summary suitable for leadership
2. Key actions taken during the response
3. Overall risk assessment
4. Suggestions for improving the playbook

Be direct and actionable. Focus on business impact and \
what matters for decision-making."""
