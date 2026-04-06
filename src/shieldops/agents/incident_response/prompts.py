"""LLM prompt templates and response schemas for the Incident Response Agent."""

from pydantic import BaseModel, Field


class AssessmentOutput(BaseModel):
    """Structured output for incident assessment."""

    severity: str = Field(description="Incident severity: critical/high/medium/low")
    assessment_score: float = Field(description="Assessment priority score 0-100")
    incident_type: str = Field(description="Type of incident detected")
    reasoning: str = Field(description="Assessment reasoning")


class ContainmentPlanOutput(BaseModel):
    """Structured output for containment planning."""

    actions: list[dict[str, str]] = Field(description="Containment actions with type, target, risk")
    auto_executable: bool = Field(description="Whether actions can be auto-executed")
    reasoning: str = Field(description="Containment reasoning")


class RecoveryPlanOutput(BaseModel):
    """Structured output for recovery planning."""

    tasks: list[dict[str, str]] = Field(description="Recovery tasks with type, service, priority")
    estimated_duration_min: int = Field(description="Estimated total recovery time in minutes")
    reasoning: str = Field(description="Recovery reasoning")


SYSTEM_ASSESS = """\
You are an expert incident responder performing initial incident assessment.

Given the incident data and context, determine:
1. Incident severity (critical, high, medium, low)
2. Assessment priority score (0-100, higher = more urgent)
3. Incident type classification

Consider: blast radius, data sensitivity, service criticality, active threat indicators."""


SYSTEM_CONTAINMENT = """\
You are an expert incident responder planning containment actions.

Given the incident assessment and affected assets:
1. Plan specific containment actions to isolate the threat
2. Assess risk level for each action
3. Determine which actions can be safely automated

Follow the principle of minimum blast radius while ensuring threat isolation."""


SYSTEM_RECOVERY = """\
You are an expert incident responder planning service recovery.

Given the incident status and affected services:
1. Plan recovery tasks in priority order
2. Estimate duration for each task
3. Identify dependencies between recovery steps

Prioritize critical services and ensure validation before declaring recovery complete."""


class TimelineSummaryOutput(BaseModel):
    """Structured output for timeline reconstruction."""

    summary: str = Field(description="Narrative summary of the incident timeline")
    attack_chain: list[str] = Field(description="Ordered list of attack phases identified")
    key_findings: list[str] = Field(description="Key findings from the investigation")
    recommended_actions: list[str] = Field(description="Recommended follow-up actions")


SYSTEM_TIMELINE = """\
You are an expert incident responder reconstructing a post-incident timeline.

Given chronological events from multiple sources (Splunk, CrowdStrike, CloudTrail, ShieldOps IR),
produce:
1. A narrative summary of what happened
2. The attack chain (initial access, execution, persistence, etc.)
3. Key findings
4. Recommended follow-up actions

Be precise and reference timestamps where possible."""
