"""LLM prompt templates and response schemas for the Adversarial Validation Agent."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class RetestSelectionOutput(BaseModel):
    """Structured output for selecting which findings to retest."""

    selected_finding_ids: list[str] = Field(
        description="IDs of red-team findings selected for revalidation"
    )
    prioritization_rationale: str = Field(
        description="Why these findings were prioritized for retesting"
    )
    expected_defense_types: list[str] = Field(
        description="Defense types expected to have been applied"
    )


class EffectivenessAssessmentOutput(BaseModel):
    """Structured output for defense effectiveness assessment."""

    per_defense: list[dict[str, Any]] = Field(
        description=(
            "Per-defense-type effectiveness with defense_type, "
            "effectiveness_pct, regression, recommendations"
        )
    )
    overall_effectiveness_pct: float = Field(
        description="Aggregate effectiveness across all defense types"
    )
    regressions: list[dict[str, Any]] = Field(
        description="Regressions found: defense_type, detail, severity"
    )
    summary: str = Field(description="Executive summary of defense effectiveness")


class PatternUpdateOutput(BaseModel):
    """Structured output for data-flywheel pattern updates."""

    updates: list[dict[str, Any]] = Field(
        description=("Pattern updates with pattern_type, old_pattern, new_pattern, source")
    )
    flywheel_summary: str = Field(description="Summary of how the red/blue flywheel advanced")


class ValidationReportOutput(BaseModel):
    """Structured output for the final validation report."""

    title: str = Field(description="Report title")
    executive_summary: str = Field(description="1-2 paragraph executive summary")
    findings_retested: int = Field(description="Number of findings retested")
    defenses_verified: int = Field(description="Number of defenses verified")
    regressions: int = Field(description="Number of regressions found")
    overall_effectiveness_pct: float = Field(description="Overall defense effectiveness")
    top_recommendations: list[str] = Field(description="Top recommendations for the security team")


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

SYSTEM_RETEST_SELECTION = """\
You are an expert adversarial validation analyst selecting which \
red-team findings should be retested after blue-team fixes.

You are given:
- A list of red-team findings that were originally successful
- The blue-team fix IDs and timestamps
- Severity levels and technique details

Your task is to:
1. Prioritize findings by severity and blast radius
2. Group related findings that exercise the same defense
3. Ensure coverage across all defense types
4. Explain your prioritization rationale

Focus on findings where a regression would be most dangerous."""

SYSTEM_EFFECTIVENESS_ASSESSMENT = """\
You are an expert security analyst assessing whether blue-team \
defenses actually neutralize red-team attack techniques.

You are given:
- Validation test results: each test re-ran an attack and recorded \
the outcome (blocked, detected, partially_blocked, bypassed, inconclusive)
- Defense types that were applied
- Confidence scores and evidence

Your task is to:
1. Calculate per-defense-type effectiveness percentages
2. Identify regressions (attacks that were previously blocked but now bypass)
3. Provide specific recommendations for each weak defense
4. Give an overall effectiveness score

Be precise: a BYPASSED outcome on a previously-fixed finding is a regression."""

SYSTEM_PATTERN_UPDATE = """\
You are a security knowledge engineer maintaining the attack/defense \
pattern databases — the data flywheel that makes the red/blue loop smarter.

You are given:
- Effectiveness scores per defense type
- Regressions and their details
- The original attack techniques and how defenses responded

Your task is to:
1. Generate updated attack patterns based on what bypassed defenses
2. Generate updated defense patterns based on what worked
3. Mark the source of each update (red_team, blue_team, validation)
4. Focus on actionable patterns that improve the next cycle

This is the CORE of the adversarial validation flywheel — each cycle \
must produce better patterns than the last."""

SYSTEM_VALIDATION_REPORT = """\
You are a senior security analyst writing the final adversarial \
validation report for executive and engineering audiences.

You are given:
- The complete validation results: findings retested, outcomes, \
effectiveness scores, regressions, pattern updates

Your task is to:
1. Write a concise executive summary
2. Highlight regressions as the highest-priority items
3. Quantify defense effectiveness with hard numbers
4. Provide top recommendations ranked by impact

Keep it crisp and action-oriented. No fluff."""
