"""LLM prompt templates and response schemas for the
Policy Compliance Enforcer Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class PolicyEvaluationOutput(BaseModel):
    """Structured output for policy evaluation."""

    violations: list[dict[str, str]] = Field(
        description=("Policy violations with policy_id, severity, and description"),
    )
    warnings: list[str] = Field(
        description="Non-blocking policy warnings",
    )
    risk_score: float = Field(
        description="Overall risk score 0-10",
    )
    compliant: bool = Field(
        description="Whether request is compliant",
    )


class ComplianceCheckOutput(BaseModel):
    """Structured output for compliance check."""

    framework_results: list[dict[str, str]] = Field(
        description=("Per-framework compliance results with control_id, status, and evidence"),
    )
    overall_compliant: bool = Field(
        description="Overall compliance status",
    )
    gaps: list[str] = Field(
        description="Compliance gaps found",
    )
    remediation_steps: list[str] = Field(
        description="Steps to achieve compliance",
    )


class EnforcementDecisionOutput(BaseModel):
    """Structured output for enforcement decision."""

    action: str = Field(
        description=("Enforcement action: allow/deny/warn/require_approval/quarantine"),
    )
    reason: str = Field(
        description="Detailed decision rationale",
    )
    policy_references: list[str] = Field(
        description="Policy IDs driving the decision",
    )
    exemption_applicable: bool = Field(
        description="Whether an exemption applies",
    )


class EnforcerReportOutput(BaseModel):
    """Structured output for enforcement report."""

    executive_summary: str = Field(
        description="Executive summary of enforcement",
    )
    total_violations: int = Field(
        description="Total violations detected",
    )
    recommendations: list[str] = Field(
        description="Recommendations for policy updates",
    )
    compliance_score: float = Field(
        description="Compliance score 0-100",
    )
    risk_rating: str = Field(
        description="Risk rating: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_EVALUATE = """\
You are an expert policy evaluation engine analyzing \
requests against security and compliance policies.

Given the request context and loaded policies:
1. Evaluate each applicable policy rule against the \
request parameters
2. Identify violations with specific policy references
3. Flag warnings for borderline conditions
4. Compute an overall risk score based on violation \
severity

Be strict on security-critical policies (IAM, data \
access, network changes) and proportionate on \
operational policies."""


SYSTEM_COMPLIANCE = """\
You are an expert compliance assessor checking requests \
against regulatory frameworks (SOC 2, HIPAA, PCI DSS, \
GDPR, FedRAMP).

Given the evaluation results and target frameworks:
1. Map violations to specific compliance controls
2. Assess whether the request meets framework requirements
3. Identify compliance gaps that need remediation
4. Provide evidence statements for audit trails

Regulatory compliance is non-negotiable. When in doubt, \
flag for human review."""


SYSTEM_ENFORCE = """\
You are an expert policy enforcement engine making \
gate decisions for infrastructure and security actions.

Given the compliance results and violation severity:
1. Determine the appropriate enforcement action
2. Check for valid exemptions that may override denials
3. Provide clear rationale for the decision
4. Reference specific policies driving the outcome

Enforcement must be consistent, auditable, and \
proportionate to risk."""


SYSTEM_REPORT = """\
You are an expert compliance reporting analyst \
synthesizing policy enforcement outcomes.

Given the full enforcement lifecycle:
1. Summarize the enforcement decision and rationale
2. List all violations and their remediation status
3. Compute compliance scores per framework
4. Recommend policy updates based on patterns

Write for compliance officers and security auditors."""
