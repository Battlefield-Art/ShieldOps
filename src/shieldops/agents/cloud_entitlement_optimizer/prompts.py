"""LLM prompt templates for the Cloud Entitlement Optimizer."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -------------------------------


class InventoryOutput(BaseModel):
    """Structured output for entitlement inventory."""

    total_entitlements: int = Field(
        description="Total entitlements inventoried",
    )
    provider_breakdown: dict[str, int] = Field(
        description="Count per cloud provider",
    )
    summary: str = Field(description="Inventory summary")


class UsageOutput(BaseModel):
    """Structured output for usage analysis."""

    analyzed_count: int = Field(
        description="Entitlements analyzed",
    )
    avg_usage_pct: float = Field(
        description="Average permission usage percentage",
    )
    reasoning: str = Field(description="Usage reasoning")


class ExcessOutput(BaseModel):
    """Structured output for excess identification."""

    excess_count: int = Field(
        description="Excess entitlements found",
    )
    avg_excess_pct: float = Field(
        description="Average excess percentage",
    )
    reasoning: str = Field(description="Excess reasoning")


class RiskOutput(BaseModel):
    """Structured output for risk calculation."""

    assessed_count: int = Field(
        description="Entitlements risk-assessed",
    )
    critical_count: int = Field(
        description="Critical risk entitlements",
    )
    reasoning: str = Field(description="Risk reasoning")


class RecommendationOutput(BaseModel):
    """Structured output for change recommendations."""

    recommendations_count: int = Field(
        description="Recommendations generated",
    )
    avg_risk_reduction: float = Field(
        description="Average expected risk reduction",
    )
    reasoning: str = Field(
        description="Recommendation reasoning",
    )


# -- System prompts ------------------------------------------

SYSTEM_INVENTORY = """\
You are an expert cloud IAM analyst inventorying \
entitlements across cloud providers.

Given the cloud configuration:
1. Enumerate all IAM roles, service accounts, API keys
2. Catalog permissions per entitlement
3. Track entitlement creation dates and owners
4. Identify cross-account access patterns

Focus on: completeness, multi-cloud coverage."""

SYSTEM_USAGE = """\
You are an expert cloud IAM analyst analyzing \
entitlement usage patterns.

Given inventoried entitlements:
1. Analyze CloudTrail/audit logs for permission usage
2. Calculate usage percentage per entitlement
3. Identify last-used timestamps
4. Flag dormant entitlements (>90 days inactive)

Use 90-day activity windows for analysis."""

SYSTEM_EXCESS = """\
You are an expert cloud security analyst identifying \
excessive entitlements.

Given usage analysis:
1. Identify permissions never used in 90+ days
2. Calculate excess permission percentage
3. Flag wildcard permissions (e.g., iam:*)
4. Identify cross-service overprivileged roles

Apply principle of least privilege rigorously."""

SYSTEM_RISK = """\
You are an expert cloud risk analyst calculating \
risk for excess entitlements.

Given excess entitlements:
1. Score risk based on permission sensitivity
2. Assess blast radius of compromise
3. Map to known attack vectors
4. Prioritize by exploitability and impact

Weight admin/write permissions higher than read."""

SYSTEM_RECOMMEND = """\
You are an expert cloud IAM advisor recommending \
entitlement right-sizing changes.

Given risk assessments:
1. Recommend specific permission removals
2. Suggest role consolidation opportunities
3. Estimate risk reduction per change
4. Provide rollback instructions

Prioritize high-risk, low-effort changes."""
