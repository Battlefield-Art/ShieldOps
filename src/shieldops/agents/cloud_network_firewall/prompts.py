"""Cloud Network Firewall Agent — LLM prompt templates and structured output schemas."""

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Structured output schemas
# ---------------------------------------------------------------------------


class CoverageOutput(BaseModel):
    """LLM output for firewall coverage analysis."""

    summary: str = Field(description="Summary of firewall rule coverage")
    weakest_area: str = Field(description="Weakest coverage area across platforms")
    coverage_gaps: list[str] = Field(description="Identified coverage gaps")
    recommendations: list[str] = Field(description="Coverage improvement recommendations")


class OverpermissiveOutput(BaseModel):
    """LLM output for overpermissive rule detection."""

    summary: str = Field(description="Summary of overpermissive rule findings")
    critical_count: int = Field(description="Number of critical overpermissive rules")
    attack_vectors: list[str] = Field(description="Attack vectors from permissive rules")
    priority_fixes: list[str] = Field(description="Prioritized fix recommendations")


class ShadowRuleOutput(BaseModel):
    """LLM output for shadow rule detection."""

    summary: str = Field(description="Summary of shadow rule analysis")
    removable_count: int = Field(description="Number of safely removable shadow rules")
    risk_assessment: str = Field(description="Risk of shadow rules remaining in place")
    cleanup_plan: list[str] = Field(description="Ordered cleanup plan for shadow rules")


class OptimizationOutput(BaseModel):
    """LLM output for rule optimization planning."""

    summary: str = Field(description="Optimization plan summary")
    merge_candidates: int = Field(description="Number of rules that can be merged")
    estimated_reduction: float = Field(description="Estimated rule count reduction percentage")
    risk_after_optimization: str = Field(description="Expected risk level post-optimization")


class FirewallReportOutput(BaseModel):
    """LLM output for final firewall report."""

    summary: str = Field(description="Executive summary of firewall posture")
    risk_level: str = Field(description="Overall risk: critical, high, medium, low")
    key_findings: list[str] = Field(description="Top firewall security findings")
    score_justification: str = Field(description="Justification for the security score")


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_COVERAGE_ANALYSIS = (
    "You are a cloud network firewall analyst.\n"
    "Analyze firewall rule coverage across cloud platforms:\n"
    "1. Evaluate ingress/egress balance and protocol coverage\n"
    "2. Identify unprotected ports and missing deny rules\n"
    "3. Assess unused rules consuming rule-table capacity\n"
    "4. Score overall coverage on a 0-100 scale"
)

SYSTEM_OVERPERMISSIVE_DETECTION = (
    "You are a firewall rule security specialist.\n"
    "Detect overly permissive firewall rules:\n"
    "1. Flag rules with 0.0.0.0/0 source on non-web ports\n"
    "2. Identify wide port ranges (e.g. 0-65535)\n"
    "3. Detect all-protocol allow rules\n"
    "4. Assess blast radius and recommend least-privilege"
)

SYSTEM_SHADOW_RULE_DETECTION = (
    "You are a firewall rule conflict analyst.\n"
    "Detect shadow rules masked by higher-priority rules:\n"
    "1. Identify rules that never match due to ordering\n"
    "2. Find conflicting allow/deny pairs on same CIDR\n"
    "3. Assess impact of shadowed deny rules\n"
    "4. Recommend safe rule cleanup ordering"
)

SYSTEM_RULE_OPTIMIZATION = (
    "You are a firewall rule optimization expert.\n"
    "Recommend optimizations for firewall rule sets:\n"
    "1. Merge overlapping rules with same action\n"
    "2. Remove redundant and shadowed rules safely\n"
    "3. Restrict overpermissive CIDRs to actual traffic\n"
    "4. Reorder rules for performance and clarity"
)

SYSTEM_FIREWALL_REPORT = (
    "You are a network security reporting analyst.\n"
    "Generate an executive firewall posture report:\n"
    "1. Summarize rule hygiene across all platforms\n"
    "2. Highlight critical overpermissive and shadow rules\n"
    "3. Quantify optimization opportunities\n"
    "4. Provide a security score with clear justification"
)
