"""LLM prompts and schemas for the Security Pipeline Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class PipelinePlanOutput(BaseModel):
    """Structured output for pipeline planning."""

    phases: list[str] = Field(description="Ordered phases to execute")
    agents_to_dispatch: list[str] = Field(description="Agent names to invoke")
    estimated_duration_minutes: int = Field(description="Estimated total duration")
    reasoning: str = Field(description="Why this plan was chosen")


class RemediationDecisionOutput(BaseModel):
    """Structured output for remediation dispatch."""

    should_remediate: bool = Field(description="Whether to auto-remediate")
    agent_name: str = Field(description="Remediation agent to dispatch")
    action: str = Field(description="Specific remediation action")
    risk_level: str = Field(description="Risk of the remediation itself")
    reasoning: str = Field(description="Justification for the decision")


class PipelineReportOutput(BaseModel):
    """Structured output for pipeline report."""

    executive_summary: str = Field(description="Summary for leadership")
    findings_total: int = Field(description="Total findings discovered")
    findings_resolved: int = Field(description="Findings remediated and verified")
    risk_reduction_pct: float = Field(description="Estimated risk reduction")
    recommendations: list[str] = Field(description="Next steps")


SYSTEM_PLAN = """\
You are a security pipeline orchestrator planning \
which agents to dispatch for a comprehensive security \
assessment.

Given the tenant context, asset inventory, and \
previous results:
1. Select appropriate discovery agents
2. Select appropriate pentest/scanner agents
3. Determine the right execution order
4. Estimate duration and resource requirements
5. Apply policy constraints

Optimize for coverage while respecting blast-radius \
limits."""


SYSTEM_REMEDIATE = """\
You are a security remediation decision engine. Given \
a finding with its severity, asset context, and \
available remediation agents:

1. Decide if auto-remediation is safe
2. Select the appropriate remediation agent
3. Specify the exact action to take
4. Assess the risk of the remediation itself

Only approve auto-remediation for confidence > 0.85. \
Escalate to human for critical infrastructure."""


SYSTEM_REPORT = """\
You are a security operations leader summarizing a \
full security pipeline run.

Given discovery, pentest, remediation, and \
verification results:
1. Write an executive summary
2. Calculate risk reduction percentage
3. Highlight unresolved critical findings
4. Provide actionable recommendations

Focus on measurable security posture improvement."""
