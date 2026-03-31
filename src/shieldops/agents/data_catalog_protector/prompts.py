"""LLM prompt templates and response schemas for the
Data Catalog Protector Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class CatalogClassificationOutput(BaseModel):
    """Structured output for sensitivity classification."""

    classifications: list[dict[str, str]] = Field(
        description="List of table classifications with sensitivity level",
    )
    pii_columns_found: list[str] = Field(
        description="PII column names detected",
    )
    unclassified_count: int = Field(
        description="Number of tables without classification",
    )
    confidence: float = Field(
        description="Overall classification confidence 0-1",
    )


class ViolationDetectionOutput(BaseModel):
    """Structured output for violation detection."""

    violations: list[dict[str, str]] = Field(
        description="Detected access violations with details",
    )
    risk_score: float = Field(
        description="Aggregate risk score 0-10",
    )
    patterns_analyzed: int = Field(
        description="Number of access patterns analyzed",
    )
    summary: str = Field(
        description="Violation analysis summary",
    )


class EnforcementRecommendationOutput(BaseModel):
    """Structured output for enforcement recommendations."""

    actions: list[dict[str, str]] = Field(
        description="Recommended enforcement actions",
    )
    priority_order: list[str] = Field(
        description="Action IDs in priority order",
    )
    estimated_risk_reduction: float = Field(
        description="Estimated risk reduction 0-1",
    )


class CatalogReportOutput(BaseModel):
    """Structured output for final catalog protection report."""

    executive_summary: str = Field(
        description="Executive summary of catalog security state",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )
    risk_rating: str = Field(
        description="Overall risk rating: critical/high/medium/low",
    )
    compliance_gaps: list[str] = Field(
        description="Identified compliance gaps",
    )


# --- System prompts ---


SYSTEM_CLASSIFICATION = """\
You are an expert data classification specialist \
analyzing data catalog entries for sensitivity.

Given the catalog scan results and table metadata:
1. Classify each table by sensitivity level \
(public, internal, confidential, restricted)
2. Identify PII columns (names, emails, SSNs, \
addresses, phone numbers, financial data)
3. Flag unclassified tables requiring manual review
4. Assess confidence based on column naming conventions \
and data sampling

Err on the side of higher sensitivity when uncertain."""


SYSTEM_VIOLATION = """\
You are an expert data access governance analyst \
detecting unauthorized access patterns.

Given the access patterns and sensitivity classifications:
1. Identify principals accessing data beyond their \
authorization level
2. Detect cross-boundary access violations between \
data domains
3. Flag excessive permissions that violate least-privilege
4. Assess severity based on data sensitivity and \
access frequency

Zero tolerance for unauthorized access to restricted data."""


SYSTEM_ENFORCEMENT = """\
You are an expert data governance enforcer recommending \
remediation actions for access violations.

Given the detected violations and current policies:
1. Recommend specific enforcement actions per violation
2. Prioritize by risk impact and blast radius
3. Suggest policy updates to prevent recurrence
4. Estimate risk reduction from each action

Balance security with business continuity."""


SYSTEM_REPORT = """\
You are an expert data governance reporter synthesizing \
catalog protection results.

Given the full scan, classification, and violation data:
1. Produce an executive summary for data governance leads
2. Highlight critical compliance gaps (GDPR, CCPA, HIPAA)
3. Recommend prioritized remediation roadmap
4. Rate overall data catalog security posture

Write clearly for both technical and executive audiences."""
