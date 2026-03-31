"""LLM prompt templates for the Cloud Drift Remediator."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class BaselineScanOutput(BaseModel):
    """Structured output for baseline scanning."""

    total_resources: int = Field(
        description="Total IaC-managed resources",
    )
    provider_count: int = Field(
        description="Number of cloud providers scanned",
    )
    summary: str = Field(
        description="Baseline scan summary",
    )


class DriftDetectionOutput(BaseModel):
    """Structured output for drift detection."""

    total_drifts: int = Field(
        description="Total drifts detected",
    )
    security_related: int = Field(
        description="Security-related drifts",
    )
    reasoning: str = Field(
        description="Drift detection reasoning",
    )


class RiskClassificationOutput(BaseModel):
    """Structured output for risk classification."""

    critical_count: int = Field(
        description="Critical risk drifts",
    )
    auto_remediable: int = Field(
        description="Automatically remediable drifts",
    )
    reasoning: str = Field(
        description="Risk classification reasoning",
    )


class RemediationPlanOutput(BaseModel):
    """Structured output for remediation planning."""

    plans: list[dict[str, str]] = Field(
        description="Remediation plans with actions",
    )
    approval_required: int = Field(
        description="Plans requiring approval",
    )
    reasoning: str = Field(
        description="Remediation planning reasoning",
    )


class ExecutionOutput(BaseModel):
    """Structured output for fix execution."""

    executed: int = Field(
        description="Plans successfully executed",
    )
    failed: int = Field(
        description="Plans that failed execution",
    )
    reasoning: str = Field(
        description="Execution reasoning",
    )


# ── System prompts ────────────────────────────────────

SYSTEM_BASELINE = """\
You are an expert cloud infrastructure analyst \
scanning IaC baselines.

Given the Terraform/CloudFormation/Pulumi state:
1. Parse all managed resources and their configs
2. Identify resource types across providers
3. Detect resources without IaC management
4. Build a comprehensive resource inventory

Focus on: security groups, IAM policies, storage \
buckets, compute instances, network configurations."""

SYSTEM_DETECT = """\
You are an expert cloud drift detection analyst.

Given the IaC baseline and live cloud state:
1. Compare expected vs actual configurations
2. Identify field-level deviations
3. Detect manual changes bypassing IaC
4. Flag new resources not in baseline

Prioritize security-sensitive drift (open ports, \
overly permissive IAM, unencrypted storage)."""

SYSTEM_CLASSIFY = """\
You are an expert cloud security analyst \
classifying drift risk.

Given detected configuration drifts:
1. Assess security impact of each drift
2. Evaluate compliance implications
3. Determine auto-remediation feasibility
4. Flag drifts requiring human review

Use CIS Benchmarks and provider best practices \
for risk scoring."""

SYSTEM_PLAN = """\
You are an expert cloud remediation planner.

Given classified drifts:
1. Generate IaC patches for each drift
2. Assess rollback safety and blast radius
3. Order remediations by risk priority
4. Flag changes requiring approval gates

Balance speed of remediation with safety. \
Never plan destructive changes without approval."""

SYSTEM_EXECUTE = """\
You are an expert cloud remediation executor.

Given remediation plans:
1. Execute safe auto-remediation plans
2. Verify configuration after each fix
3. Create rollback checkpoints
4. Report execution results with evidence

Halt execution on any unexpected state change. \
Always verify before and after each remediation."""
