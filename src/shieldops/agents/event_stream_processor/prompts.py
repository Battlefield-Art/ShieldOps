"""Event Stream Processor Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class EnrichmentInsight(BaseModel):
    """Structured output from event enrichment analysis."""

    summary: str = Field(
        description="Brief enrichment overview",
    )
    high_risk_sources: list[str] = Field(
        description="Source IPs or hosts with elevated risk",
    )
    ioc_matches: list[str] = Field(
        description="IOC values matched during enrichment",
    )


class CorrelationInsight(BaseModel):
    """Structured output from correlation rule analysis."""

    summary: str = Field(
        description="Correlation analysis overview",
    )
    top_rules_fired: list[str] = Field(
        description="Names of the most significant rules that fired",
    )
    attack_patterns: list[str] = Field(
        description="Identified MITRE ATT&CK patterns",
    )


class RoutingInsight(BaseModel):
    """Structured output from routing decision analysis."""

    summary: str = Field(
        description="Routing decision overview",
    )
    high_priority_destinations: list[str] = Field(
        description="Destinations receiving critical alerts",
    )
    recommendations: list[str] = Field(
        description="Routing tuning recommendations",
    )


class ReportInsight(BaseModel):
    """Structured output for the final stream-processor report."""

    summary: str = Field(
        description="Executive summary of stream processing session",
    )
    key_findings: list[str] = Field(
        description="Key security findings from the event stream",
    )
    next_steps: list[str] = Field(
        description="Recommended follow-up actions",
    )


SYSTEM_ENRICH = (
    "You are a security event enrichment analyst reviewing "
    "parsed events from a real-time stream.\n"
    "1. Identify source IPs with elevated risk scores\n"
    "2. Flag IOC matches and their severity\n"
    "3. Highlight ASN/geo patterns that indicate threats\n"
    "4. Summarize enrichment quality and coverage"
)

SYSTEM_CORRELATE = (
    "You are a correlation rules analyst working on a "
    "real-time security event pipeline.\n"
    "1. Assess which correlation rules fired with highest confidence\n"
    "2. Map rules to MITRE ATT&CK techniques\n"
    "3. Identify multi-stage attack sequences\n"
    "4. Flag false positive candidates for tuning"
)

SYSTEM_REPORT = (
    "You are a SOC engineering lead generating a "
    "real-time event stream processing report.\n"
    "1. Summarize throughput, parse rates, and enrichment coverage\n"
    "2. Highlight critical correlations and destinations reached\n"
    "3. Quantify the volume of high-severity alerts routed\n"
    "4. Recommend stream topology or rule-set improvements"
)
