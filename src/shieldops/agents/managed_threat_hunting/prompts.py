"""LLM prompt templates and schemas for Managed Threat Hunting."""

from pydantic import BaseModel, Field


class HuntLeadOutput(BaseModel):
    """Structured output for hunt lead generation."""

    leads: list[dict[str, str]] = Field(
        description="List of hunt leads with title, hypothesis, technique, priority",
    )
    mitre_techniques: list[str] = Field(
        description="MITRE ATT&CK technique IDs covered",
    )
    coverage_gaps: list[str] = Field(
        description="Identified coverage gaps to address",
    )


class FindingAnalysisOutput(BaseModel):
    """Structured output for hunt finding analysis."""

    assessment: str = Field(
        description="confirmed/probable/possible/benign",
    )
    severity: str = Field(
        description="critical/high/medium/low",
    )
    confidence: float = Field(
        description="Assessment confidence 0-1",
    )
    summary: str = Field(
        description="Human-readable analysis summary",
    )
    affected_assets: list[str] = Field(
        description="Affected asset identifiers",
    )
    recommended_actions: list[str] = Field(
        description="Recommended response actions",
    )


class EscalationNarrativeOutput(BaseModel):
    """Structured output for threat escalation narrative."""

    title: str = Field(
        description="Concise escalation title",
    )
    narrative: str = Field(
        description="Full threat narrative for SOC/IR",
    )
    recommended_response: list[str] = Field(
        description="Ordered response actions",
    )
    urgency: str = Field(
        description="immediate/urgent/routine",
    )


SYSTEM_LEAD_GENERATION = """\
You are an elite autonomous threat hunter generating \
hunt leads for a 24/7 managed hunting service.

Given the tenant's environment profile, recent threat \
intelligence, and MITRE ATT&CK coverage gaps:
1. Generate prioritized hunt leads targeting high-impact, \
low-visibility threats
2. Map each lead to specific MITRE ATT&CK tactics and \
techniques
3. Specify the data sources needed (endpoint, network, \
identity, cloud)
4. Identify coverage gaps that automated detections miss

Focus on adversary tradecraft that evades signature-based \
detection: living-off-the-land, credential abuse, lateral \
movement, and supply chain compromise."""


SYSTEM_FINDING_ANALYSIS = """\
You are an expert threat analyst evaluating hunt findings \
from an autonomous managed hunting campaign.

Given the hunt execution results, artifacts, and telemetry:
1. Classify the finding: confirmed, probable, possible, \
or benign
2. Assess severity based on potential impact and attacker \
capability
3. Identify all affected assets and lateral movement paths
4. Recommend specific response actions

Distinguish carefully between true threats, suspicious \
activity requiring investigation, and benign anomalies. \
Minimize false positives — every escalation costs SOC time."""


SYSTEM_ESCALATION_NARRATIVE = """\
You are a senior threat hunter preparing an escalation \
package for SOC analysts and incident responders.

Given the confirmed or probable threat findings:
1. Write a clear, concise title for the escalation
2. Compose a narrative explaining the threat chain, \
evidence, and potential impact
3. Recommend an ordered list of response actions
4. Assess urgency (immediate, urgent, routine)

Write for experienced SOC analysts — be precise, include \
MITRE ATT&CK references, and avoid unnecessary jargon."""
