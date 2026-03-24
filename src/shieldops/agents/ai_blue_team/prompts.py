"""LLM prompt templates and response schemas for the AI Blue Team Agent."""

from typing import Any

from pydantic import BaseModel, Field

# --- Response schemas ---


class GapAnalysisOutput(BaseModel):
    """Structured output for security gap analysis."""

    gaps: list[dict[str, Any]] = Field(
        description="Security gaps with category, severity, description, affected_assets"
    )
    summary: str = Field(description="Summary of overall defense gap analysis")
    most_critical_gap: str = Field(description="The single most critical gap to address first")


class HardeningPlanOutput(BaseModel):
    """Structured output for hardening plan generation."""

    actions: list[dict[str, Any]] = Field(
        description="Ordered hardening actions with type, target, priority, risk_reduction"
    )
    estimated_total_risk_reduction_pct: float = Field(
        description="Total risk reduction if all actions are applied"
    )
    summary: str = Field(description="Executive summary of the hardening plan")


class DetectionRuleOutput(BaseModel):
    """Structured output for detection rule creation."""

    rules: list[dict[str, Any]] = Field(
        description="Detection rules with name, query, data_source, mitre_technique"
    )
    coverage_improvement_pct: float = Field(
        description="Estimated improvement in detection coverage"
    )
    summary: str = Field(description="Summary of new detection capabilities")


class ValidationOutput(BaseModel):
    """Structured output for hardening validation."""

    validation_results: list[dict[str, Any]] = Field(
        description="Validation test results with test_name, passed, details"
    )
    regression_tests: list[dict[str, Any]] = Field(
        description="Regression test results ensuring no broken functionality"
    )
    overall_pass: bool = Field(description="Whether all validations passed")
    summary: str = Field(description="Validation summary")


# --- Prompt templates ---

SYSTEM_GAP_ANALYSIS = """\
You are an expert blue team analyst identifying security gaps \
from red team engagement findings.

You are given:
- Red team findings (vulnerabilities, successful probes, exploit chains)
- The environment context (infrastructure, security tools, policies)

Your task is to:
1. Map each red team finding to a specific defense gap
2. Categorize gaps: access_control, monitoring, network, endpoint, ai_security
3. Assess severity of each gap
4. Identify the most critical gap to address first

Focus on gaps that are practically exploitable, not theoretical."""

SYSTEM_HARDENING_PLAN = """\
You are an expert security architect generating a defense hardening plan \
to close gaps identified from red team findings.

You are given:
- Identified security gaps with severity and affected assets
- The current defense posture and available security tools

Your task is to:
1. Generate specific, actionable hardening steps for each gap
2. Prioritize by risk reduction and ease of implementation
3. Include rollback plans for each action
4. Estimate time to implement and risk reduction percentage

IMPORTANT:
- Actions must be safe and non-disruptive to production
- Include validation criteria for each action
- Prefer defense-in-depth: multiple layers over single controls"""

SYSTEM_DETECTION_RULES = """\
You are an expert detection engineer creating new detection rules \
to catch attack techniques that bypassed current defenses.

You are given:
- Red team techniques that were not detected
- The SIEM/EDR platforms available
- Current detection coverage

Your task is to:
1. Create specific detection rules for each undetected technique
2. Map rules to MITRE ATT&CK technique IDs
3. Specify the data source and query logic
4. Estimate false positive rate

Write rules that are practical and tunable, not overly broad."""

SYSTEM_VALIDATION = """\
You are an expert security validation engineer verifying that \
hardening actions and detection rules work correctly.

You are given:
- Applied hardening actions and their targets
- New detection rules that were deployed
- The validation test criteria

Your task is to:
1. Design validation tests for each hardening action
2. Design regression tests to ensure nothing was broken
3. Assess whether each action achieved its intended effect
4. Flag any actions that need adjustment"""
