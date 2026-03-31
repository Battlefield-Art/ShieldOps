"""LLM prompt templates and response schemas for the
Cloud Governance Enforcer Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class TagComplianceOutput(BaseModel):
    """Structured output for tag compliance analysis."""

    non_compliant_resources: list[str] = Field(
        description="Resource IDs missing required tags",
    )
    common_missing_tags: list[str] = Field(
        description="Most frequently missing tags",
    )
    naming_violations_count: int = Field(
        description="Number of naming convention violations",
    )
    compliance_score: float = Field(
        description="Overall tag compliance score 0-1",
    )


class PolicyEvaluationOutput(BaseModel):
    """Structured output for policy evaluation."""

    violations_found: int = Field(
        description="Number of policy violations detected",
    )
    critical_violations: list[str] = Field(
        description="Critical violation descriptions",
    )
    cost_attribution_gaps: list[str] = Field(
        description="Resources without cost attribution",
    )
    lifecycle_issues: list[str] = Field(
        description="Resource lifecycle policy issues",
    )


class ViolationAnalysisOutput(BaseModel):
    """Structured output for violation analysis."""

    total_violations: int = Field(
        description="Total violations detected",
    )
    by_severity: dict[str, int] = Field(
        description="Violation counts by severity",
    )
    auto_remediable_count: int = Field(
        description="Violations that can be auto-remediated",
    )
    estimated_cost_impact: float = Field(
        description="Estimated monthly cost of violations",
    )
    priority_actions: list[str] = Field(
        description="Top priority remediation actions",
    )


class GovernanceReportOutput(BaseModel):
    """Structured output for final governance report."""

    executive_summary: str = Field(
        description="Executive summary of governance status",
    )
    compliance_score: float = Field(
        description="Overall compliance score 0-100",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )
    risk_assessment: str = Field(
        description="Overall governance risk assessment",
    )
    cost_optimization_opportunities: list[str] = Field(
        description="Cost savings from better governance",
    )


# --- System prompts ---


SYSTEM_TAG_COMPLIANCE = """\
You are an expert cloud governance analyst evaluating \
tag compliance across multi-cloud infrastructure.

Given the resource inventory and required tag policies:
1. Identify resources missing mandatory tags (env, owner, \
cost-center, team, project)
2. Detect naming convention violations
3. Find orphaned resources without proper attribution
4. Score overall tag compliance

Focus on cost attribution, security classification, and \
operational ownership tags."""


SYSTEM_POLICY_EVALUATION = """\
You are an expert cloud policy evaluator assessing \
resources against governance policies.

Given tag compliance results and resource metadata:
1. Evaluate against lifecycle policies (idle resources, \
expiration, right-sizing)
2. Check cost attribution completeness
3. Verify naming conventions per cloud provider standards
4. Identify security-relevant policy gaps

Prioritize violations that affect cost control and \
security posture."""


SYSTEM_VIOLATION_ANALYSIS = """\
You are an expert cloud governance analyst classifying \
and prioritizing detected violations.

Given policy evaluation results:
1. Classify violations by severity and blast radius
2. Identify which violations are auto-remediable
3. Estimate cost impact of non-compliance
4. Recommend prioritized remediation sequence

Balance automation with human oversight for critical \
infrastructure changes."""


SYSTEM_REPORT = """\
You are an expert cloud governance advisor producing \
an enforcement report for leadership.

Given the full governance scan results:
1. Produce an executive summary of compliance posture
2. Highlight critical risks and immediate actions
3. Quantify cost optimization opportunities
4. Recommend governance maturity improvements

Write clearly for both cloud engineering and finance \
audiences."""
