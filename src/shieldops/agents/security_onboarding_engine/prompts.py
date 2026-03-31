"""LLM prompt templates and response schemas for the
Security Onboarding Engine Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class RiskAssessmentOutput(BaseModel):
    """Structured output for risk profile assessment."""

    risk_score: float = Field(
        description="Overall risk score 0-10",
    )
    risk_level: str = Field(
        description="Risk level: critical/high/medium/low",
    )
    compliance_requirements: list[str] = Field(
        description="Applicable compliance frameworks",
    )
    threat_vectors: list[str] = Field(
        description="Primary threat vectors for this service",
    )
    data_sensitivity: str = Field(
        description="Data sensitivity assessment",
    )


class RequirementGenerationOutput(BaseModel):
    """Structured output for requirement generation."""

    requirements: list[dict[str, str]] = Field(
        description="Security requirements with title, category, priority",
    )
    mandatory_count: int = Field(
        description="Number of mandatory requirements",
    )
    framework_mappings: list[str] = Field(
        description="Compliance framework mappings",
    )
    estimated_effort: str = Field(
        description="Estimated implementation effort",
    )


class ValidationOutput(BaseModel):
    """Structured output for control validation."""

    passed: int = Field(
        description="Number of controls that passed validation",
    )
    failed: int = Field(
        description="Number of controls that failed validation",
    )
    compliance_met: bool = Field(
        description="Whether minimum compliance threshold is met",
    )
    gaps: list[str] = Field(
        description="Identified security gaps",
    )
    remediation_needed: list[str] = Field(
        description="Controls requiring remediation",
    )


class OnboardingReportOutput(BaseModel):
    """Structured output for onboarding report."""

    executive_summary: str = Field(
        description="Executive summary of onboarding outcome",
    )
    readiness_score: float = Field(
        description="Security readiness score 0-100",
    )
    recommendations: list[str] = Field(
        description="Post-onboarding recommendations",
    )
    next_review_date: str = Field(
        description="Recommended next security review date",
    )


# --- System prompts ---


SYSTEM_RISK = """\
You are an expert security risk assessor evaluating \
the risk profile of a new service being onboarded.

Given the service details (tech stack, data classification, \
exposure, tier):
1. Calculate a risk score based on data sensitivity and \
attack surface
2. Identify applicable compliance frameworks (SOC2, HIPAA, \
PCI-DSS, GDPR)
3. Map primary threat vectors specific to the tech stack
4. Assess data sensitivity considering classification and \
external exposure

Be thorough — missed risk factors during onboarding \
create long-term security debt."""


SYSTEM_REQUIREMENTS = """\
You are an expert security architect generating security \
requirements for a new service.

Given the service risk profile and compliance obligations:
1. Generate specific, measurable security requirements
2. Categorize by type (access control, encryption, logging, \
network, vulnerability management)
3. Prioritize based on risk score and compliance mandates
4. Map to compliance framework controls

Requirements must be actionable and testable — vague \
requirements lead to incomplete implementations."""


SYSTEM_VALIDATE = """\
You are an expert security validator assessing whether \
provisioned controls meet requirements.

Given the provisioned controls and original requirements:
1. Validate each control against its requirement
2. Identify gaps where controls are missing or insufficient
3. Determine if minimum compliance thresholds are met
4. List controls requiring remediation

Be strict — gaps found now prevent incidents later."""


SYSTEM_REPORT = """\
You are an expert security operations reporter summarizing \
service onboarding outcomes.

Given the full onboarding results (intake, risk, \
requirements, controls, validation):
1. Produce an executive summary for security leadership
2. Calculate a security readiness score
3. Provide prioritized post-onboarding recommendations
4. Suggest the next security review cadence

Write for both the service team and security governance."""
