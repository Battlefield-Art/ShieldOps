"""LLM prompt templates for the Security Automation Pipeline Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# -- Structured output schemas -----------------------------------------


class PipelineScanOutput(BaseModel):
    """Structured output for pipeline scanning."""

    pipelines_found: int = Field(
        description="Total pipelines scanned",
    )
    missing_gates_total: int = Field(
        description="Total missing security gates",
    )
    summary: str = Field(
        description="Pipeline scan summary",
    )


class GateInjectionOutput(BaseModel):
    """Structured output for gate injection."""

    gates_injected: int = Field(
        description="Number of security gates injected",
    )
    blocking_gates: int = Field(
        description="Number of blocking gates",
    )
    reasoning: str = Field(
        description="Gate injection reasoning",
    )


class CheckResultsOutput(BaseModel):
    """Structured output for security check results."""

    total_findings: int = Field(
        description="Total findings across all checks",
    )
    critical_findings: int = Field(
        description="Number of critical findings",
    )
    reasoning: str = Field(
        description="Check results reasoning",
    )


class EvaluationOutput(BaseModel):
    """Structured output for gate evaluation."""

    gates_passed: int = Field(
        description="Number of gates passed",
    )
    gates_failed: int = Field(
        description="Number of gates failed",
    )
    reasoning: str = Field(
        description="Evaluation reasoning",
    )


class EnforcementOutput(BaseModel):
    """Structured output for gate enforcement."""

    actions: list[dict[str, str]] = Field(
        description="Enforcement actions taken",
    )
    pipelines_blocked: int = Field(
        description="Number of pipelines blocked",
    )
    reasoning: str = Field(
        description="Enforcement reasoning",
    )


# -- System prompts ----------------------------------------------------

SYSTEM_SCAN = """\
You are an expert security automation engineer scanning \
CI/CD pipeline configurations.

Given the scan configuration:
1. Identify all CI/CD pipelines across repositories
2. Audit existing security gates and scan stages
3. Detect missing SAST, DAST, SCA, and secret scanning
4. Assess pipeline security risk scores

Focus on: GitHub Actions, GitLab CI, Jenkins, \
CircleCI, and Azure DevOps pipelines."""

SYSTEM_INJECT = """\
You are an expert security automation engineer injecting \
security gates into pipelines.

Given the pipeline scan results:
1. Determine optimal gate placement in each pipeline
2. Configure SAST, DAST, SCA, and container scanning
3. Set appropriate thresholds for blocking vs warning
4. Ensure gates do not break existing pipeline flow

Balance security coverage with developer experience."""

SYSTEM_CHECK = """\
You are an expert security automation engineer evaluating \
security check results.

Given the security gate configurations:
1. Run SAST analysis for code vulnerabilities
2. Execute SCA for dependency vulnerabilities
3. Perform secret detection in code and configs
4. Validate container images against security policies

Prioritize findings by exploitability and business impact."""

SYSTEM_EVALUATE = """\
You are an expert security automation engineer evaluating \
gate pass/fail decisions.

Given the check results:
1. Apply threshold policies to each gate result
2. Determine pass/fail status for blocking gates
3. Identify findings eligible for risk acceptance
4. Generate override recommendations for edge cases

Consider: severity, exploitability, and compensating \
controls."""

SYSTEM_ENFORCE = """\
You are an expert security automation engineer enforcing \
security gate decisions.

Given the gate evaluations:
1. Block deployments that fail critical gates
2. Generate PR comments for failed checks
3. Create tickets for non-blocking findings
4. Record enforcement decisions in audit trail

Ensure zero bypasses for critical/high severity gates."""
