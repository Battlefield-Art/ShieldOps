"""LLM prompt templates and response schemas for the
Security Event Enricher Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ContextLookupOutput(BaseModel):
    """Structured output for context lookup."""

    asset_criticality: str = Field(
        description="Asset criticality: critical/high/medium/low",
    )
    user_risk: str = Field(
        description="User risk profile assessment",
    )
    geo_anomaly: bool = Field(
        description="Whether geo location is anomalous",
    )
    summary: str = Field(
        description="Context summary for analysts",
    )


class ThreatEnrichmentOutput(BaseModel):
    """Structured output for threat intel enrichment."""

    ioc_matches: list[str] = Field(
        description="Matched indicators of compromise",
    )
    mitre_techniques: list[str] = Field(
        description="Mapped MITRE ATT&CK techniques",
    )
    threat_actor: str = Field(
        description="Attributed threat actor if known",
    )
    confidence: float = Field(
        description="Enrichment confidence 0-1",
    )


class PriorityScoringOutput(BaseModel):
    """Structured output for priority scoring."""

    priority: str = Field(
        description="Priority: critical/high/medium/low",
    )
    score: float = Field(
        description="Numeric priority score 0-10",
    )
    factors: list[str] = Field(
        description="Factors contributing to the score",
    )
    auto_actionable: bool = Field(
        description="Whether auto-response is recommended",
    )


class EnrichmentReportOutput(BaseModel):
    """Structured output for the enrichment report."""

    executive_summary: str = Field(
        description="Summary of enrichment pipeline run",
    )
    critical_events: int = Field(
        description="Count of critical events",
    )
    recommendations: list[str] = Field(
        description="Recommendations for SOC team",
    )
    pipeline_health: str = Field(
        description="Pipeline health: healthy/degraded/down",
    )


# --- System prompts ---


SYSTEM_CONTEXT = """\
You are an expert security analyst enriching events \
with asset, user, and geolocation context.

Given a raw security event:
1. Assess the criticality of the affected asset
2. Evaluate the user risk profile and behavior history
3. Detect geographic anomalies (impossible travel, \
unusual locations)
4. Summarize the context for rapid analyst triage

Prioritize context that changes the event severity."""


SYSTEM_THREAT_ENRICHMENT = """\
You are an expert threat intelligence analyst enriching \
security events with IOC and campaign data.

Given a security event with context:
1. Match indicators against threat intelligence feeds
2. Map the activity to MITRE ATT&CK techniques
3. Attribute to known threat actors or campaigns
4. Assess confidence in the threat attribution

Focus on actionable intelligence that enables response."""


SYSTEM_PRIORITY = """\
You are an expert SOC analyst scoring security event \
priority for triage and routing.

Given an enriched event with context and threat intel:
1. Score priority based on asset criticality, threat \
severity, and business impact
2. Identify contributing factors for the score
3. Determine if automated response is appropriate
4. Recommend SLA targets for investigation

Balance speed with accuracy to avoid alert fatigue."""


SYSTEM_REPORT = """\
You are an expert security operations reporter \
summarizing enrichment pipeline results.

Given the full enrichment run (events, context, \
threat intel, scoring, routing):
1. Produce a pipeline run summary for SOC leadership
2. Highlight critical events requiring immediate action
3. Recommend tuning improvements for the pipeline
4. Assess overall pipeline health and throughput

Write clearly for operational handoff."""
