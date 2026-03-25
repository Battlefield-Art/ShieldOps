"""LLM prompt templates and response schemas for the Incident Triage Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ClassificationOutput(BaseModel):
    """Structured output for LLM-assisted severity classification."""

    severity: str = Field(description="Severity level: sev1/sev2/sev3/sev4/sev5")
    category: str = Field(
        description=(
            "Incident category: security_breach/availability/performance/"
            "data_loss/compliance/configuration"
        )
    )
    confidence: str = Field(description="Confidence: high/medium/low/uncertain")
    reasoning: str = Field(description="Explanation for the classification")


class EnrichmentOutput(BaseModel):
    """Structured output for LLM-assisted context enrichment."""

    blast_radius: str = Field(description="Estimated blast radius description")
    likely_root_cause: str = Field(description="Most likely root cause hypothesis")
    recommended_runbook: str = Field(description="Suggested runbook or procedure name")
    urgency_factors: list[str] = Field(description="Key factors that increase or decrease urgency")


class RoutingOutput(BaseModel):
    """Structured output for LLM-assisted routing decisions."""

    assigned_team: str = Field(description="Team best suited to handle this incident")
    escalation_required: bool = Field(description="Whether management escalation is needed")
    auto_remediation_possible: bool = Field(
        description="Whether automated remediation can be attempted"
    )
    routing_reasoning: str = Field(description="Explanation for the routing decision")


class ReportOutput(BaseModel):
    """Structured output for LLM-generated triage summary."""

    executive_summary: str = Field(description="One-paragraph executive summary")
    key_findings: list[str] = Field(description="Top findings from triage")
    recommended_actions: list[str] = Field(description="Prioritized action items")
    risk_assessment: str = Field(description="Overall risk assessment: critical/high/medium/low")


SYSTEM_CLASSIFY = """\
You are an expert incident triage analyst performing severity classification.

Given the incident title, description, alerts, and affected services, determine:
1. Severity level (sev1 = critical, sev2 = high, sev3 = medium, sev4 = low, sev5 = informational)
2. Incident category (security_breach, availability, performance, \
data_loss, compliance, configuration)
3. Confidence in your classification (high, medium, low, uncertain)

Consider: blast radius, data sensitivity, customer impact, active threat indicators, \
time of day, and historical patterns. Err on the side of higher severity when uncertain."""


SYSTEM_ENRICH = """\
You are an expert incident analyst enriching incident context.

Given the incident details and affected services, determine:
1. Blast radius — how many services, customers, and regions are impacted
2. Most likely root cause hypothesis based on available signals
3. Recommended runbook or standard operating procedure
4. Key urgency factors that should influence triage priority

Use your knowledge of common failure modes and incident patterns."""


SYSTEM_ROUTE = """\
You are an expert incident commander making routing decisions.

Given the incident classification and enrichment context, determine:
1. Which team should own this incident (security-ops, platform-sre, data-engineering, \
governance-risk-compliance, devops)
2. Whether management escalation is required
3. Whether automated remediation can be safely attempted

Route based on incident category, severity, confidence level, and blast radius. \
Escalate SEV1/SEV2 incidents and any with uncertain classification."""


SYSTEM_REPORT = """\
You are an expert incident analyst generating a triage summary report.

Given all triage results (classifications, enrichments, routing decisions), produce:
1. A concise executive summary suitable for leadership
2. Key findings from the triage process
3. Prioritized recommended actions
4. Overall risk assessment

Be direct and actionable. Focus on what matters for decision-making."""
