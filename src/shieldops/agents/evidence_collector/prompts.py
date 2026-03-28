"""LLM prompt templates and response schemas for the Evidence Collector."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SourceIdentOutput(BaseModel):
    """Structured output for evidence source identification."""

    sources: list[dict[str, str]] = Field(description="Identified evidence sources")
    priority_order: list[str] = Field(description="Collection priority order")
    reasoning: str = Field(description="Reasoning for source selection")


class IntegrityOutput(BaseModel):
    """Structured output for integrity assessment."""

    status: str = Field(description="Status: verified/tampered/unknown")
    confidence: float = Field(description="Confidence in assessment 0.0-1.0")
    notes: str = Field(description="Assessment notes")


class PackageOutput(BaseModel):
    """Structured output for evidence packaging."""

    package_name: str = Field(description="Evidence package identifier")
    included_artifacts: list[str] = Field(description="Artifacts included")
    classification: str = Field(description="Evidence classification level")


class ReportOutput(BaseModel):
    """Structured output for evidence collection summary."""

    executive_summary: str = Field(description="Summary of evidence collected")
    artifacts_collected: int = Field(description="Total artifacts collected")
    integrity_status: str = Field(description="Overall integrity status")
    chain_of_custody_complete: bool = Field(description="Whether chain of custody is intact")
    recommendations: list[str] = Field(description="Follow-up recommendations")


SYSTEM_IDENTIFY_SOURCES = """\
You are an expert digital forensics analyst \
identifying evidence sources.

Given the incident type and affected systems:
1. Identify all relevant evidence sources
2. Prioritize by volatility (collect volatile first)
3. Note any legal or compliance requirements

Follow the order of volatility: memory > running \
processes > network > disk > external logs."""


SYSTEM_VERIFY_INTEGRITY = """\
You are an expert forensics examiner verifying \
evidence integrity.

Given the artifact metadata and hash values:
1. Assess whether integrity is maintained
2. Flag any signs of tampering
3. Recommend additional verification steps

Integrity is critical for legal admissibility."""


SYSTEM_PACKAGE = """\
You are an expert forensics analyst packaging \
evidence for handoff.

Given the collected artifacts and their metadata:
1. Determine appropriate packaging and labeling
2. Classify evidence sensitivity level
3. Ensure chain of custody documentation

Follow forensic best practices for evidence \
preservation."""


SYSTEM_REPORT = """\
You are an expert forensics analyst generating \
an evidence collection report.

Given all artifacts, verifications, and custody \
records:
1. Summarize what was collected
2. Assess overall integrity
3. Confirm chain of custody completeness
4. Recommend additional collection if needed

Be precise and legally defensible."""
