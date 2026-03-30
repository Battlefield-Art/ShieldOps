"""Threat Feed Aggregator Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class CorrelationInsight(BaseModel):
    """Structured output from threat correlation."""

    summary: str = Field(
        description="Brief correlation overview",
    )
    campaigns: list[str] = Field(
        description="Identified threat campaigns",
    )
    attack_patterns: list[str] = Field(
        description="Detected attack patterns",
    )


class EnrichmentInsight(BaseModel):
    """Structured output from IOC enrichment."""

    summary: str = Field(
        description="Enrichment summary",
    )
    high_risk_iocs: list[str] = Field(
        description="Highest-risk IOCs identified",
    )
    threat_actors: list[str] = Field(
        description="Associated threat actors",
    )


class DistributionInsight(BaseModel):
    """Structured output for intel distribution."""

    summary: str = Field(
        description="Distribution summary",
    )
    priority_targets: list[str] = Field(
        description="Priority distribution targets",
    )
    recommendations: list[str] = Field(
        description="Distribution recommendations",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive threat intel summary",
    )
    key_findings: list[str] = Field(
        description="Key findings for leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_CORRELATE = (
    "You are a threat intelligence analyst "
    "correlating indicators of compromise.\n"
    "1. Identify IOCs appearing across feeds\n"
    "2. Map IOCs to known threat campaigns\n"
    "3. Detect MITRE ATT&CK technique patterns\n"
    "4. Assess threat actor attribution"
)

SYSTEM_REPORT = (
    "You are a CTI analyst generating an "
    "executive threat intelligence report.\n"
    "1. Summarize total IOCs and severity\n"
    "2. Highlight active threat campaigns\n"
    "3. Quantify risk exposure from findings\n"
    "4. Recommend defensive mitigations"
)
