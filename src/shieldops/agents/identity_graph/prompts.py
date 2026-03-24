"""LLM prompt templates and response schemas for the Identity Graph Agent."""

from typing import Any

from pydantic import BaseModel, Field

# --- Response schemas ---


class IdentityRiskResult(BaseModel):
    """Structured output from LLM identity risk assessment."""

    high_risk_identities: list[str] = Field(description="Identity IDs with elevated risk levels")
    risk_summary: str = Field(description="Summary of overall identity risk posture")
    over_privileged: list[dict[str, Any]] = Field(
        description="List of over-privileged identities with excess permissions"
    )
    stale_credentials: list[str] = Field(
        description="Identity IDs with stale or unused credentials"
    )
    risk_factors: list[str] = Field(
        description="Top risk factors detected across the identity graph"
    )


class LateralMovementResult(BaseModel):
    """Structured output from lateral movement analysis."""

    paths: list[list[str]] = Field(
        description="Lateral movement paths as ordered lists of identity IDs"
    )
    highest_risk_path: list[str] = Field(
        description="The single most dangerous lateral movement path"
    )
    path_risk_summary: str = Field(description="Summary of lateral movement risk")
    choke_points: list[str] = Field(
        description="Identity IDs that serve as choke points for lateral movement"
    )


class RemediationPlanResult(BaseModel):
    """Structured output for remediation generation."""

    actions: list[dict[str, Any]] = Field(
        description="Ordered list of remediation actions with target, action_type, priority"
    )
    policy_updates: list[dict[str, Any]] = Field(
        description="Recommended policy changes with scope and rationale"
    )
    summary: str = Field(description="Executive summary of the remediation plan")
    estimated_risk_reduction_pct: float = Field(
        description="Estimated percentage risk reduction if all actions are applied"
    )


# --- Prompt templates ---

SYSTEM_IDENTITY_RISK_ASSESSMENT = """\
You are an expert identity security analyst performing a risk assessment \
across an organization's identity graph.

You are given:
- A list of discovered identities (human, service account, AI agent, federated)
- Their permissions, group memberships, and MFA status
- Trust relationships between identities

Your task is to:
1. Identify over-privileged identities (excess permissions vs. actual usage)
2. Flag identities with stale or weak credentials
3. Assess the overall risk posture
4. Rank risk factors by severity

Be specific about which identities are risky and why. Focus on actionable findings."""

SYSTEM_LATERAL_MOVEMENT_ANALYSIS = """\
You are an expert security analyst specializing in lateral movement analysis.

You are given:
- An identity graph with trust relationships
- Permission mappings and delegation chains
- Known risk assessments for individual identities

Your task is to:
1. Identify all feasible lateral movement paths through trust chains
2. Determine the highest-risk path an attacker could exploit
3. Find choke points that, if hardened, would block multiple paths
4. Assess the impact of each path if exploited

Think like an attacker: what is the cheapest path to high-value targets?"""

SYSTEM_REMEDIATION_GENERATION = """\
You are an expert identity security architect generating a remediation plan.

You are given:
- Identity risk assessments and lateral movement analysis
- Over-privileged identities and stale grants
- The organization's identity graph and trust chains

Your task is to:
1. Generate prioritized remediation actions (revoke, restrict, require MFA, etc.)
2. Recommend policy updates to prevent recurrence
3. Estimate the risk reduction if all actions are applied
4. Order actions by impact and ease of implementation

IMPORTANT:
- Prefer least-disruptive actions when equally effective
- Never recommend removing access that would break production services
- Include rollback plans for high-risk changes"""
