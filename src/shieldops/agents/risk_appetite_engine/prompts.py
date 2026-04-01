"""LLM prompt templates for the Risk Appetite Engine Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ── Structured output schemas ─────────────────────────


class AppetiteDefinitionOutput(BaseModel):
    """Structured output for appetite definition."""

    categories_defined: int = Field(
        description="Risk categories defined",
    )
    avg_threshold: float = Field(
        description="Average threshold value",
    )
    summary: str = Field(description="Appetite summary")


class ExposureMeasureOutput(BaseModel):
    """Structured output for exposure measurement."""

    categories_measured: int = Field(
        description="Categories measured",
    )
    highest_exposure: str = Field(
        description="Highest exposure category",
    )
    confidence_avg: float = Field(
        description="Average measurement confidence",
    )
    reasoning: str = Field(description="Measurement reasoning")


class ThresholdCompareOutput(BaseModel):
    """Structured output for threshold comparison."""

    within_tolerance: int = Field(
        description="Categories within tolerance",
    )
    exceeding: int = Field(
        description="Categories exceeding tolerance",
    )
    reasoning: str = Field(description="Comparison reasoning")


class BreachIdentifyOutput(BaseModel):
    """Structured output for breach identification."""

    breaches_found: int = Field(
        description="Threshold breaches found",
    )
    critical_breaches: int = Field(
        description="Critical severity breaches",
    )
    reasoning: str = Field(description="Breach analysis reasoning")


class AdjustmentOutput(BaseModel):
    """Structured output for adjustment recommendations."""

    recommendations_count: int = Field(
        description="Recommendations generated",
    )
    expected_reduction_avg: float = Field(
        description="Average expected risk reduction",
    )
    reasoning: str = Field(
        description="Adjustment reasoning",
    )


# ── System prompts ────────────────────────────────────

SYSTEM_DEFINE_APPETITE = """\
You are an expert risk management advisor defining \
organizational risk appetite.

Given the organization's risk configuration:
1. Define tolerance levels per risk category
2. Set quantitative thresholds for each category
3. Align with regulatory and board requirements
4. Document risk appetite rationale

Focus on: regulatory alignment, business context, \
measurable thresholds."""

SYSTEM_MEASURE_EXPOSURE = """\
You are an expert risk analyst measuring current risk \
exposure across categories.

Given the risk appetite definitions:
1. Collect exposure data from security tools
2. Quantify current risk levels per category
3. Assess data confidence and coverage gaps
4. Identify trending risk areas

Use multiple data sources for accuracy."""

SYSTEM_COMPARE_THRESHOLDS = """\
You are an expert risk analyst comparing actual \
exposure against defined thresholds.

Given appetite definitions and exposure measurements:
1. Calculate delta between actual and threshold
2. Classify as within-tolerance or exceeding
3. Identify categories approaching limits
4. Assess trend direction for each category

Flag categories within 10% of threshold as warnings."""

SYSTEM_IDENTIFY_BREACHES = """\
You are an expert risk analyst identifying threshold \
breaches requiring action.

Given threshold comparisons:
1. Identify all categories exceeding tolerance
2. Assess breach severity and duration
3. Calculate overshoot percentage
4. Estimate business impact of each breach

Prioritize breaches by severity and duration."""

SYSTEM_RECOMMEND = """\
You are an expert risk advisor recommending adjustments \
to reduce risk exposure.

Given identified breaches and risk context:
1. Propose specific remediation actions
2. Estimate expected risk reduction per action
3. Assess implementation effort and timeline
4. Prioritize recommendations by impact

Balance quick wins against structural improvements."""
