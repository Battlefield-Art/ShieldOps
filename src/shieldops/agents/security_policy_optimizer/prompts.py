"""LLM prompt templates for the Security Policy Optimizer Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class PolicyCollectionOutput(BaseModel):
    """Structured output for policy collection."""

    total_policies: int = Field(description="Total policies collected")
    enabled_count: int = Field(description="Number of enabled policies")
    summary: str = Field(description="Collection summary")


class EffectivenessAnalysisOutput(BaseModel):
    """Structured output for effectiveness analysis."""

    high_fp_count: int = Field(description="Policies with high false-positive rate")
    low_precision_count: int = Field(description="Policies with low precision")
    reasoning: str = Field(description="Effectiveness analysis reasoning")


class OptimizationIdentificationOutput(BaseModel):
    """Structured output for optimization identification."""

    optimizations_found: int = Field(description="Number of optimizations identified")
    estimated_fp_reduction: float = Field(description="Estimated overall FP reduction 0-1")
    reasoning: str = Field(description="Optimization identification reasoning")


class ChangeApplicationOutput(BaseModel):
    """Structured output for change application."""

    changes_applied: int = Field(description="Number of changes applied")
    rollback_available: int = Field(description="Changes with rollback available")
    reasoning: str = Field(description="Change application reasoning")


class ChangeValidationOutput(BaseModel):
    """Structured output for change validation."""

    validations_passed: int = Field(description="Number of validations passed")
    validations_failed: int = Field(description="Number of validations failed")
    reasoning: str = Field(description="Validation reasoning")


# ── System prompts ────────────────────────────────────

SYSTEM_COLLECT_POLICIES = """\
You are an expert security policy engineer collecting \
policies for optimization review.

Given the collection configuration:
1. Enumerate all active security policies across sources
2. Categorize by network, identity, data, application, endpoint, cloud
3. Note policy age, trigger frequency, and enabled status
4. Flag overly broad or duplicate rules

Focus on: comprehensive coverage, accurate categorization, \
identifying stale or redundant policies."""

SYSTEM_ANALYZE_EFFECTIVENESS = """\
You are an expert security policy analyst evaluating \
policy effectiveness using telemetry data.

Given the collected policies and their metrics:
1. Calculate precision and recall for each rule
2. Identify rules with high false-positive rates
3. Detect rules that never trigger (dead rules)
4. Assess rules with low coverage or high miss rates

Prioritize rules that cause the most analyst fatigue \
through excessive false positives."""

SYSTEM_IDENTIFY_OPTIMIZATIONS = """\
You are an expert security policy optimizer identifying \
improvements to reduce noise and tighten security.

Given effectiveness metrics:
1. Recommend tightening overly permissive rules
2. Suggest merging overlapping rules to reduce duplication
3. Propose threshold adjustments to reduce false positives
4. Identify rules safe to deprecate based on zero coverage

Balance: reducing false positives without increasing \
false negatives or creating security gaps."""

SYSTEM_APPLY_CHANGES = """\
You are an expert security policy engineer applying \
optimizations to live policies.

Given the optimization recommendations:
1. Apply changes with rollback capability
2. Preserve original rule state for audit trail
3. Validate change compatibility with dependent rules
4. Stage changes for validation before full deployment

Ensure all changes are reversible and auditable."""

SYSTEM_VALIDATE_CHANGES = """\
You are an expert security policy validator verifying \
that applied changes maintain security posture.

Given applied changes and validation telemetry:
1. Verify coverage has not decreased below threshold
2. Confirm false-positive rate has improved
3. Check for regression in detection capabilities
4. Validate no security gaps introduced by changes

Flag any validation failure for immediate rollback."""
