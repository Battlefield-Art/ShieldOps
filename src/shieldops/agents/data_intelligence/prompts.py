"""Data Intelligence Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class DiscoveryInsight(BaseModel):
    """Structured output from data discovery."""

    summary: str = Field(description="Data discovery overview")
    shadow_data: list[str] = Field(description="Potential shadow data stores")
    coverage_gaps: list[str] = Field(description="Areas lacking data visibility")


class ClassificationInsight(BaseModel):
    """Structured output from AI classification."""

    summary: str = Field(description="Classification overview")
    high_sensitivity: list[str] = Field(description="High sensitivity data sources")
    regulatory_concerns: list[str] = Field(description="Regulatory compliance concerns")


class LineageInsight(BaseModel):
    """Structured output from lineage mapping."""

    summary: str = Field(description="Lineage mapping overview")
    cross_border_risks: list[str] = Field(description="Cross-border data flow risks")
    dependency_chains: list[str] = Field(description="Critical data dependency chains")


class RiskInsight(BaseModel):
    """Structured output from data risk assessment."""

    summary: str = Field(description="Data risk overview")
    critical_exposures: list[str] = Field(description="Critical data exposure risks")
    protection_priorities: list[str] = Field(description="Top protection priorities")


SYSTEM_DISCOVER = (
    "You are a data discovery analyst scanning "
    "for data sources across the enterprise.\n"
    "1. Identify unmanaged or shadow data stores\n"
    "2. Flag data sources without encryption\n"
    "3. Detect stale or abandoned data sets\n"
    "4. Assess data source diversity and coverage"
)

SYSTEM_CLASSIFY = (
    "You are an AI-powered data classifier.\n"
    "1. Identify PII, PHI, and PCI data elements\n"
    "2. Map data to regulatory frameworks\n"
    "3. Assess classification confidence levels\n"
    "4. Flag data needing manual review"
)

SYSTEM_LINEAGE = (
    "You are a data lineage analyst mapping "
    "data flows across systems.\n"
    "1. Trace data from source to consumption\n"
    "2. Identify cross-border data transfers\n"
    "3. Map transformation pipelines\n"
    "4. Flag broken or stale lineage links"
)

SYSTEM_RISK = (
    "You are a data risk analyst assessing "
    "data exposure and compliance.\n"
    "1. Score data risk based on sensitivity and exposure\n"
    "2. Identify access control violations\n"
    "3. Map compliance gaps to frameworks\n"
    "4. Recommend protection priorities"
)
