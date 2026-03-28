"""LLM prompt templates and response schemas for the IOC Lifecycle Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ValidationOutput(BaseModel):
    """Structured output for IOC validation."""

    valid_count: int = Field(description="Number of valid IOCs")
    invalid_count: int = Field(description="Number of invalid IOCs")
    reasoning: str = Field(description="Reasoning for validation")


class EnrichmentOutput(BaseModel):
    """Structured output for IOC enrichment analysis."""

    threat_score: float = Field(
        description="Threat score 0.0-1.0",
    )
    category: str = Field(description="Threat category")
    reasoning: str = Field(description="Enrichment reasoning")


class ClassificationOutput(BaseModel):
    """Structured output for IOC classification."""

    severity: str = Field(
        description="Severity: critical/high/medium/low",
    )
    kill_chain_phase: str = Field(
        description="Kill chain phase",
    )
    is_false_positive: bool = Field(
        description="Whether IOC is a false positive",
    )
    reasoning: str = Field(
        description="Classification reasoning",
    )


class ReportOutput(BaseModel):
    """Structured output for IOC lifecycle report."""

    executive_summary: str = Field(
        description="Summary of IOC lifecycle analysis",
    )
    active_iocs: int = Field(description="Active IOC count")
    false_positives: int = Field(
        description="False positive count",
    )
    recommendations: list[str] = Field(
        description="Follow-up recommendations",
    )


SYSTEM_VALIDATE = """\
You are an expert threat intelligence analyst \
validating indicators of compromise.

Given the collected IOCs:
1. Check format validity (IP ranges, hash lengths, etc.)
2. Identify obviously benign indicators
3. Flag duplicates or near-duplicates

Validate strictly — only confirmed IOCs proceed."""


SYSTEM_ENRICH = """\
You are an expert threat intelligence analyst \
enriching indicators of compromise.

Given an IOC and its metadata:
1. Assess threat score based on available intelligence
2. Identify associated malware families or campaigns
3. Determine geographic and network context

Use multiple intelligence sources for correlation."""


SYSTEM_CLASSIFY = """\
You are an expert threat intelligence analyst \
classifying indicators of compromise.

Given an IOC with enrichment data:
1. Assign severity (critical/high/medium/low)
2. Map to MITRE ATT&CK kill chain phase
3. Determine if this is a false positive

Be conservative — false positives waste SOC time."""


SYSTEM_REPORT = """\
You are an expert threat intelligence analyst \
generating an IOC lifecycle report.

Given all IOCs, enrichments, and classifications:
1. Summarize the threat landscape
2. Highlight critical and aged indicators
3. Recommend retirement or re-validation actions
4. Identify false positive patterns

Be precise and actionable for SOC analysts."""
