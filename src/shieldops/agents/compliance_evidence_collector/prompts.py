"""LLM prompt templates for the Compliance Evidence Collector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -----------------------------------------


class ControlIdentificationOutput(BaseModel):
    """Structured output for control identification."""

    total_controls: int = Field(
        description="Total controls identified",
    )
    automated_count: int = Field(
        description="Number of automatable controls",
    )
    summary: str = Field(
        description="Control identification summary",
    )


class EvidenceCollectionOutput(BaseModel):
    """Structured output for evidence collection."""

    collected_count: int = Field(
        description="Number of evidence items collected",
    )
    missing_count: int = Field(
        description="Number of missing evidence items",
    )
    reasoning: str = Field(
        description="Collection reasoning",
    )


class ValidationOutput(BaseModel):
    """Structured output for evidence validation."""

    valid_count: int = Field(
        description="Number of valid evidence items",
    )
    insufficient_count: int = Field(
        description="Number of insufficient items",
    )
    reasoning: str = Field(
        description="Validation reasoning",
    )


class FrameworkMappingOutput(BaseModel):
    """Structured output for framework mapping."""

    coverage_pct: float = Field(
        description="Overall coverage percentage 0-100",
    )
    gap_count: int = Field(
        description="Number of coverage gaps",
    )
    reasoning: str = Field(
        description="Framework mapping reasoning",
    )


class ReportOutput(BaseModel):
    """Structured output for compliance report generation."""

    sections: list[dict[str, str]] = Field(
        description="Report sections with framework and summary",
    )
    overall_readiness: float = Field(
        description="Overall audit readiness 0-100",
    )
    reasoning: str = Field(
        description="Report generation reasoning",
    )


# -- System prompts ----------------------------------------------------

SYSTEM_IDENTIFY = """\
You are an expert compliance auditor identifying \
control requirements for evidence collection.

Given the scan configuration and target frameworks:
1. Enumerate all applicable control requirements
2. Map controls to evidence types (logs, configs, screenshots)
3. Identify automatable vs manual evidence collection
4. Prioritize controls by audit criticality

Focus on: SOC2 Trust Services Criteria, ISO 27001 Annex A, \
HIPAA Security Rule, PCI-DSS requirements."""

SYSTEM_COLLECT = """\
You are an expert compliance auditor collecting \
evidence artifacts.

Given the identified controls:
1. Collect system logs and audit trails
2. Capture configuration snapshots and screenshots
3. Gather policy documents and procedures
4. Extract access control lists and user reviews

Ensure evidence is timestamped, immutable, and traceable."""

SYSTEM_VALIDATE = """\
You are an expert compliance auditor validating \
collected evidence.

Given the evidence items:
1. Verify evidence completeness for each control
2. Check evidence freshness (within audit period)
3. Validate evidence authenticity and integrity
4. Identify gaps requiring additional collection

Apply professional skepticism and materiality thresholds."""

SYSTEM_MAP = """\
You are an expert compliance auditor mapping controls \
across frameworks.

Given the validated evidence:
1. Map controls to multiple framework requirements
2. Identify cross-framework synergies
3. Calculate coverage percentage per framework
4. Highlight gaps and remediation needs

Use common control frameworks (NIST CSF, CIS Controls) \
as the mapping backbone."""

SYSTEM_REPORT = """\
You are an expert compliance auditor generating \
an audit-ready compliance report.

Given the framework mappings and evidence status:
1. Summarize readiness per framework
2. Highlight critical gaps and remediation timeline
3. Provide evidence inventory with traceability
4. Recommend next steps for audit preparation

Structure for auditor consumption with clear \
evidence references."""
