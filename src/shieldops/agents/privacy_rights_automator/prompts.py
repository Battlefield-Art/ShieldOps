"""LLM prompt templates and response schemas for the
Privacy Rights Automator Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class DataLocationOutput(BaseModel):
    """Structured output for data location discovery."""

    locations: list[dict[str, str]] = Field(
        description="Discovered data locations with system, table, owner",
    )
    pii_categories: list[str] = Field(
        description="PII categories found across systems",
    )
    cross_border_transfers: list[str] = Field(
        description="Systems with cross-border data transfers",
    )
    confidence: float = Field(
        description="Overall confidence in location discovery 0-1",
    )


class PIIClassificationOutput(BaseModel):
    """Structured output for PII classification."""

    classifications: list[dict[str, str]] = Field(
        description="PII field classifications with sensitivity",
    )
    high_risk_fields: list[str] = Field(
        description="Fields requiring special handling",
    )
    retention_risks: list[str] = Field(
        description="Data retention compliance risks",
    )
    summary: str = Field(
        description="Classification summary for compliance team",
    )


class ActionValidationOutput(BaseModel):
    """Structured output for action validation."""

    validated: bool = Field(
        description="Whether the action plan is compliant",
    )
    risks: list[str] = Field(
        description="Compliance risks in the action plan",
    )
    recommendations: list[str] = Field(
        description="Recommendations before execution",
    )
    regulatory_notes: list[str] = Field(
        description="Regulation-specific considerations",
    )


class ComplianceReportOutput(BaseModel):
    """Structured output for final compliance report."""

    executive_summary: str = Field(
        description="Executive summary of request fulfillment",
    )
    request_fulfilled: bool = Field(
        description="Whether the request was fully fulfilled",
    )
    recommendations: list[str] = Field(
        description="Recommendations for process improvement",
    )
    compliance_gaps: list[str] = Field(
        description="Identified compliance gaps",
    )
    compliance_rating: str = Field(
        description="Compliance rating: full/partial/non_compliant",
    )


# --- System prompts ---


SYSTEM_LOCATE = """\
You are an expert privacy engineer locating personal \
data across enterprise systems.

Given the data subject identity and system inventory:
1. Identify all systems likely to contain subject data
2. Map data flows to discover secondary storage
3. Flag cross-border transfers requiring extra scrutiny
4. Prioritize systems by data sensitivity and volume

Be thorough: missed data locations cause compliance \
violations and regulatory fines."""


SYSTEM_CLASSIFY = """\
You are an expert data classification specialist \
analyzing PII across discovered locations.

Given the discovered data locations and field metadata:
1. Classify each field by PII category and sensitivity
2. Identify special category data (health, biometric, \
financial)
3. Assess retention policy compliance per regulation
4. Flag fields requiring encryption or pseudonymization

Accuracy is critical: misclassification leads to \
improper handling of sensitive data."""


SYSTEM_VALIDATE = """\
You are an expert privacy compliance validator reviewing \
a proposed action plan for a data subject request.

Given the request type, regulation, and planned actions:
1. Validate the plan meets regulatory requirements
2. Identify risks of data leakage during processing
3. Ensure proper audit trails are maintained
4. Check that data portability formats meet standards

Regulatory compliance is non-negotiable."""


SYSTEM_REPORT = """\
You are an expert privacy compliance reporter \
synthesizing request fulfillment results.

Given the full request lifecycle (locations, \
classifications, actions, verifications):
1. Produce an executive summary for the DPO
2. Document compliance with applicable regulations
3. Identify process improvements for future requests
4. Rate overall compliance of the fulfillment

Write for regulatory auditors and legal counsel."""
