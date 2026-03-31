"""LLM prompt templates and response schemas for the
Kubernetes Policy Engine Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ResourceScanOutput(BaseModel):
    """Structured output for resource scanning."""

    resource_count: int = Field(
        description="Total K8s resources scanned",
    )
    namespaces_covered: list[str] = Field(
        description="Namespaces scanned",
    )
    risk_areas: list[str] = Field(
        description="Identified risk areas in cluster",
    )
    recommendations: list[str] = Field(
        description="Immediate recommendations",
    )


class PolicyEvaluationOutput(BaseModel):
    """Structured output for policy evaluation."""

    violations_found: int = Field(
        description="Number of policy violations",
    )
    critical_count: int = Field(
        description="Critical violations count",
    )
    policies_evaluated: int = Field(
        description="Number of policies evaluated",
    )
    summary: str = Field(
        description="Policy evaluation summary",
    )


class StandardsCheckOutput(BaseModel):
    """Structured output for standards compliance."""

    compliant: bool = Field(
        description="Whether cluster meets standards",
    )
    standards_checked: list[str] = Field(
        description="Standards evaluated",
    )
    gaps: list[str] = Field(
        description="Compliance gaps found",
    )
    score: float = Field(
        description="Compliance score 0-100",
    )


class EnforcementReportOutput(BaseModel):
    """Structured output for enforcement report."""

    executive_summary: str = Field(
        description="Executive summary of findings",
    )
    total_violations: int = Field(
        description="Total violations detected",
    )
    enforced_count: int = Field(
        description="Violations auto-remediated",
    )
    recommendations: list[str] = Field(
        description="Prioritized recommendations",
    )
    compliance_score: float = Field(
        description="Overall compliance score 0-100",
    )


# --- System prompts ---


SYSTEM_SCAN = """\
You are an expert Kubernetes security engineer \
scanning cluster resources for policy evaluation.

Given the cluster context and namespaces:
1. Identify all resource types requiring policy evaluation
2. Flag resources with privileged configurations
3. Detect missing security contexts and resource limits
4. Highlight RBAC misconfigurations and excessive permissions

Focus on Pod Security Standards (baseline/restricted), \
network policy gaps, and admission control weaknesses."""


SYSTEM_EVALUATE = """\
You are an expert Kubernetes policy evaluator assessing \
resources against security policies.

Given scanned resources and policy rules:
1. Evaluate each resource against applicable policies
2. Classify violations by severity and blast radius
3. Identify cascading policy failures across namespaces
4. Recommend specific remediation for each violation

Prioritize findings by exploitability and business impact."""


SYSTEM_STANDARDS = """\
You are an expert Kubernetes compliance assessor checking \
cluster adherence to security standards.

Given evaluation results and standards frameworks:
1. Map findings to CIS Kubernetes Benchmark controls
2. Check Pod Security Standards (baseline, restricted)
3. Validate network segmentation and egress controls
4. Assess RBAC against least-privilege principles

Provide actionable remediation steps for each gap."""


SYSTEM_REPORT = """\
You are an expert Kubernetes security reporter synthesizing \
policy engine findings.

Given all violations, standards results, and enforcement:
1. Produce an executive summary for platform engineering
2. Prioritize remediation by risk and effort
3. Calculate overall compliance posture score
4. Recommend policy tuning and admission webhook changes

Write clearly for both security and platform teams."""
