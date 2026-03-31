"""LLM prompt templates and response schemas for the
Cloud Resource Tagger Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ResourceScanOutput(BaseModel):
    """Structured output for resource scanning."""

    resources: list[dict[str, str]] = Field(
        description="Discovered resources with type, provider, region",
    )
    untagged_count: int = Field(
        description="Count of resources with missing required tags",
    )
    providers_scanned: list[str] = Field(
        description="Cloud providers scanned",
    )
    confidence: float = Field(
        description="Scan completeness confidence 0-1",
    )


class TagGenerationOutput(BaseModel):
    """Structured output for tag generation."""

    recommendations: list[dict[str, str]] = Field(
        description="Tag recommendations with key, value, resource",
    )
    auto_generated: int = Field(
        description="Count of auto-generated tags",
    )
    patterns_detected: list[str] = Field(
        description="Naming patterns detected for inference",
    )
    summary: str = Field(
        description="Tag generation summary",
    )


class ComplianceValidationOutput(BaseModel):
    """Structured output for tag compliance validation."""

    compliant_count: int = Field(
        description="Number of compliant resources",
    )
    non_compliant_count: int = Field(
        description="Number of non-compliant resources",
    )
    violations: list[str] = Field(
        description="Specific compliance violations",
    )
    compliance_pct: float = Field(
        description="Overall compliance percentage 0-100",
    )


class TagReportOutput(BaseModel):
    """Structured output for tagging report."""

    executive_summary: str = Field(
        description="Executive summary of tagging status",
    )
    total_resources: int = Field(
        description="Total resources scanned",
    )
    compliance_rate: float = Field(
        description="Tag compliance rate 0-100",
    )
    recommendations: list[str] = Field(
        description="Recommendations for improving compliance",
    )


# --- System prompts ---


SYSTEM_SCAN = """\
You are an expert cloud resource inventory analyst \
scanning multi-cloud environments for untagged resources.

Given the cloud environment scope:
1. Identify all resources across AWS, GCP, and Azure
2. Check each resource against required tag policies
3. Flag resources with missing or non-compliant tags
4. Prioritize by cost impact and compliance risk

Focus on high-cost and compliance-sensitive resources."""


SYSTEM_TAG_GENERATION = """\
You are an expert cloud tagging strategist generating \
tag recommendations from resource metadata.

Given untagged resources and their metadata:
1. Infer appropriate tag values from naming conventions
2. Apply organizational tagging standards
3. Detect patterns across similar resources
4. Generate cost-center and ownership tags

Maintain consistency with existing tag conventions."""


SYSTEM_COMPLIANCE = """\
You are an expert cloud compliance auditor validating \
resource tags against organizational policies.

Given tagged resources and compliance policies:
1. Validate all required tags are present
2. Check tag values against allowed value lists
3. Identify compliance gaps by provider and region
4. Score overall tag compliance

Be strict — missing required tags are violations."""


SYSTEM_REPORT = """\
You are an expert cloud operations reporter summarizing \
resource tagging status for stakeholders.

Given the tagging analysis results:
1. Produce a compliance summary with key metrics
2. Highlight the most impactful gaps
3. Recommend automation improvements
4. Project compliance trajectory

Write for both FinOps and security audiences."""
