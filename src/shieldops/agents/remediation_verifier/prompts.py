"""LLM prompt templates for Remediation Verifier Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TestDesignResult(BaseModel):
    """Structured output for test design."""

    test_type: str = Field(
        description=("Test type: rescan, exploit_retest, config_check, access_check, policy_check")
    )
    description: str = Field(description="What the test verifies")
    expected_outcome: str = Field(description="Expected result if fix worked")


class AssessmentResult(BaseModel):
    """Structured output for result assessment."""

    overall_result: str = Field(
        description=("fixed, partially_fixed, not_fixed, regression, new_issue")
    )
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in the assessment")
    details: str = Field(description="Assessment details")
    needs_attention: bool = Field(description="Needs human attention?")


class VerifierReportResult(BaseModel):
    """Structured output for the verifier report."""

    title: str = Field(description="Report title")
    executive_summary: str = Field(description="1-2 sentence summary")
    risk_assessment: str = Field(description="Overall risk: low, medium, high")
    action_items: list[str] = Field(description="Follow-up actions needed")


SYSTEM_DESIGN_TEST = """\
You are a security verification expert. Given a \
completed remediation, design a verification test to \
confirm the fix actually worked.

Consider:
1. What was the original vulnerability?
2. What fix was applied?
3. What test would confirm the fix?
4. What is the expected outcome if fixed?

Choose the most appropriate test type."""

SYSTEM_ASSESS = """\
You are a security verification expert assessing \
whether a remediation fix was successful. Given the \
test execution results, determine:

1. Overall result (fixed, partially, not_fixed, etc.)
2. Confidence level (0.0-1.0)
3. Whether human attention is needed
4. Detailed assessment

Be conservative — if unsure, flag for attention."""

SYSTEM_REPORT = """\
You are a security verification expert generating a \
verification report. Summarize remediations verified, \
test results, regressions found, and remaining risks.

Keep the report concise and actionable."""
