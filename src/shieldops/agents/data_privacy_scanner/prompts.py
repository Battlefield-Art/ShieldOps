"""LLM prompt templates and response schemas for the
Data Privacy Scanner Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class DataClassificationOutput(BaseModel):
    """Structured output for data classification."""

    classifications: list[dict[str, str]] = Field(
        description=("Classifications with field_name, category, and confidence"),
    )
    pii_fields: list[str] = Field(
        description="Fields containing PII data",
    )
    phi_fields: list[str] = Field(
        description="Fields containing PHI data",
    )
    pci_fields: list[str] = Field(
        description="Fields containing PCI data",
    )


class PIIDetectionOutput(BaseModel):
    """Structured output for PII detection analysis."""

    findings: list[dict[str, str]] = Field(
        description="PII findings with type, severity, and field",
    )
    total_pii_records: int = Field(
        description="Total records containing PII",
    )
    masked_count: int = Field(
        description="Records with proper masking",
    )
    unprotected_count: int = Field(
        description="Records without masking or encryption",
    )


class DataFlowOutput(BaseModel):
    """Structured output for data flow mapping."""

    flows: list[dict[str, str]] = Field(
        description="Data flows with source, destination, and category",
    )
    cross_border_flows: int = Field(
        description="Number of cross-border data transfers",
    )
    unencrypted_flows: int = Field(
        description="Number of unencrypted data transfers",
    )
    risk_score: float = Field(
        description="Data flow risk score 0-10",
    )


class PrivacyReportOutput(BaseModel):
    """Structured output for final privacy report."""

    executive_summary: str = Field(
        description="Executive summary for privacy leadership",
    )
    critical_findings: list[str] = Field(
        description="Critical privacy findings",
    )
    compliance_gaps: list[str] = Field(
        description="Compliance gaps by regime",
    )
    recommendations: list[str] = Field(
        description="Actionable remediation recommendations",
    )
    overall_score: float = Field(
        description="Privacy compliance score 0-100",
    )


# --- System prompts ---


SYSTEM_CLASSIFY = """\
You are an expert data classification analyst identifying \
sensitive data across enterprise datastores.

Given the datastore metadata and sample field information:
1. Classify each field by data category (PII, PHI, PCI, \
confidential, internal, public)
2. Identify specific PII types (SSN, email, name, phone, \
address, DOB)
3. Detect PHI indicators (medical records, diagnoses, \
treatment data)
4. Flag PCI data (card numbers, CVV, expiration dates)

Be thorough: missed PII causes compliance violations."""


SYSTEM_PII = """\
You are an expert privacy analyst detecting PII, PHI, \
and PCI data in enterprise systems.

Given the classified data fields and sample records:
1. Confirm PII presence with pattern matching evidence
2. Assess whether data is properly masked or encrypted
3. Identify records at highest risk of exposure
4. Flag any data that violates retention policies

Precision matters: both false positives and false \
negatives have compliance consequences."""


SYSTEM_FLOWS = """\
You are an expert data flow analyst mapping sensitive \
data movement across systems.

Given the datastores and their interconnections:
1. Map data flows between source and destination systems
2. Identify cross-border data transfers (GDPR Art. 44+)
3. Check encryption status for data in transit
4. Flag data flows that bypass security controls

Cross-border flows of PII require special attention \
under GDPR and CCPA."""


SYSTEM_REPORT = """\
You are an expert privacy compliance analyst synthesizing \
data privacy scan results.

Given the full scan (datastores, classifications, PII \
findings, data flows, compliance assessments):
1. Produce an executive summary for privacy leadership
2. Highlight critical findings requiring immediate action
3. Assess compliance posture per regime (GDPR, CCPA, etc.)
4. Provide specific remediation recommendations

Write clearly for DPOs, legal counsel, and engineering."""
