"""Policy Engine Agent — LLM prompt templates and structured output schemas."""

from pydantic import BaseModel, Field


class RequirementsOutput(BaseModel):
    """Structured output from LLM-assisted requirements analysis."""

    summary: str = Field(description="Brief summary of security requirements analysis")
    priority_requirements: list[str] = Field(
        description="High-priority requirements that need immediate policy coverage"
    )
    framework_gaps: list[str] = Field(
        description="Compliance framework areas lacking requirement definitions"
    )
    recommendations: list[str] = Field(
        description="Recommendations for additional security requirements"
    )


class PolicyGenerationOutput(BaseModel):
    """Structured output from LLM-assisted policy generation."""

    summary: str = Field(description="Brief summary of generated policies")
    policy_rationale: list[str] = Field(description="Rationale for each generated policy")
    rego_improvements: list[str] = Field(
        description="Suggested improvements to generated Rego code"
    )
    edge_cases: list[str] = Field(description="Edge cases the policies should handle")


class CoverageOutput(BaseModel):
    """Structured output from LLM-assisted coverage validation."""

    summary: str = Field(description="Brief summary of coverage validation results")
    critical_gaps: list[str] = Field(
        description="Critical coverage gaps requiring immediate attention"
    )
    partial_coverage: list[str] = Field(
        description="Requirements with partial but incomplete coverage"
    )
    remediation_steps: list[str] = Field(description="Steps to close identified coverage gaps")


class DriftOutput(BaseModel):
    """Structured output from LLM-assisted drift detection."""

    summary: str = Field(description="Brief summary of drift detection results")
    root_causes: list[str] = Field(description="Root causes of detected policy drift")
    impact_assessment: list[str] = Field(description="Impact of each drift on security posture")
    reconciliation_priority: list[str] = Field(
        description="Prioritized list of drifts to reconcile"
    )


SYSTEM_REQUIREMENTS_ANALYSIS = (
    "You are a security policy analyst reviewing security requirements.\n"
    "For the given tenant and compliance context:\n"
    "1. Identify high-priority requirements that need immediate policy coverage\n"
    "2. Flag compliance framework areas lacking requirement definitions\n"
    "3. Recommend additional security requirements based on best practices\n"
    "4. Assess whether existing requirements are automatable via OPA policies"
)

SYSTEM_POLICY_GENERATION = (
    "You are an OPA Rego policy engineer generating policies from requirements.\n"
    "For each security requirement:\n"
    "1. Determine the appropriate OPA package namespace "
    "(e.g., shieldops.access_control)\n"
    "2. Generate valid Rego code with default deny, explicit allow rules\n"
    "3. Include input validation and proper error messages in policy metadata\n"
    "4. Map each policy to the requirements it satisfies for traceability"
)

SYSTEM_COVERAGE_VALIDATION = (
    "You are a security coverage analyst validating policy completeness.\n"
    "For the generated policies and requirements:\n"
    "1. Verify every security requirement has at least one covering policy\n"
    "2. Identify partial coverage where policies exist but are incomplete\n"
    "3. Assess the severity of each coverage gap based on risk exposure\n"
    "4. Suggest specific Rego policy additions to close critical gaps"
)

SYSTEM_DRIFT_DETECTION = (
    "You are a policy drift analyst comparing deployed vs defined state.\n"
    "For each active policy:\n"
    "1. Compare the defined Rego code against the deployed OPA bundle\n"
    "2. Identify configuration drift, rule modifications, and missing policies\n"
    "3. Classify drift severity based on security impact\n"
    "4. Determine which drifts can be auto-reconciled vs require manual review"
)
