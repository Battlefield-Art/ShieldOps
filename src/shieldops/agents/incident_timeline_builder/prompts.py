"""Incident Timeline Builder Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class CorrelationInsight(BaseModel):
    """Structured output from event correlation."""

    summary: str = Field(
        description="Brief correlation overview",
    )
    key_clusters: list[str] = Field(
        description="Identified event clusters",
    )
    anomalies: list[str] = Field(
        description="Anomalous event patterns",
    )


class RootCauseInsight(BaseModel):
    """Structured output from root cause analysis."""

    summary: str = Field(
        description="Root cause summary",
    )
    attack_chain: list[str] = Field(
        description="Sequence of attacker actions",
    )
    evidence: list[str] = Field(
        description="Supporting evidence for root cause",
    )


class NarrativeInsight(BaseModel):
    """Structured output for incident narrative."""

    summary: str = Field(
        description="Executive summary of the incident",
    )
    key_events: list[str] = Field(
        description="Most significant timeline events",
    )
    lessons_learned: list[str] = Field(
        description="Lessons learned and improvements",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of incident timeline",
    )
    key_findings: list[str] = Field(
        description="Key findings for leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_CORRELATE = (
    "You are a security analyst correlating events "
    "from multiple sources into an incident timeline.\n"
    "1. Identify events sharing hosts, users, or IPs\n"
    "2. Detect temporal clustering within windows\n"
    "3. Flag anomalous patterns across sources\n"
    "4. Score correlation confidence per cluster"
)

SYSTEM_ROOT_CAUSE = (
    "You are a senior incident responder performing "
    "root cause analysis on correlated events.\n"
    "1. Identify the initial access vector\n"
    "2. Map the attack chain chronologically\n"
    "3. Determine MITRE ATT&CK techniques used\n"
    "4. Assess contributing factors and gaps"
)

SYSTEM_NARRATIVE = (
    "You are a security analyst writing an incident "
    "narrative from a reconstructed timeline.\n"
    "1. Produce a clear executive summary\n"
    "2. Walk through the attack chronologically\n"
    "3. Assess business impact\n"
    "4. Recommend containment and remediation steps"
)

SYSTEM_REPORT = (
    "You are a CISO advisor generating an incident "
    "timeline report for leadership.\n"
    "1. Summarize timeline scope and root cause\n"
    "2. Highlight the most critical findings\n"
    "3. Quantify affected assets and duration\n"
    "4. Recommend next steps for prevention"
)
