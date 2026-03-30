"""LLM prompt templates and response schemas for SOC Metrics Analyzer."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --------------- Structured output schemas ---------------


class PerformanceAssessmentOutput(BaseModel):
    """LLM output for metric performance assessment."""

    assessments: list[dict[str, str]] = Field(
        description=("Per-category assessment with keys: category, trend, assessment, factors"),
    )
    overall_health: str = Field(
        description="Overall SOC health: healthy/degraded/critical",
    )
    confidence: float = Field(
        description="Confidence in the assessment 0-1",
    )


class BottleneckDetectionOutput(BaseModel):
    """LLM output for bottleneck detection."""

    bottlenecks: list[dict[str, str]] = Field(
        description=(
            "Detected bottlenecks with keys: name, severity, description, root_cause, impact_score"
        ),
    )
    systemic_issues: list[str] = Field(
        description="Cross-cutting systemic issues",
    )
    reasoning: str = Field(
        description="Reasoning behind bottleneck detection",
    )


class BenchmarkAnalysisOutput(BaseModel):
    """LLM output for industry benchmark comparison."""

    benchmark_assessments: list[dict[str, str]] = Field(
        description=(
            "Per-metric benchmark with keys: metric_name, assessment, improvement_priority"
        ),
    )
    competitive_position: str = Field(
        description=(
            "Overall competitive position: leading/above_average/average/below_average/lagging"
        ),
    )
    key_gaps: list[str] = Field(
        description="Top gaps versus industry leaders",
    )


class RecommendationOutput(BaseModel):
    """LLM output for improvement recommendations."""

    recommendations: list[dict[str, str]] = Field(
        description=(
            "Recommendations with keys: title, "
            "priority, description, expected_impact, "
            "effort, steps"
        ),
    )
    quick_wins: list[str] = Field(
        description="Immediately actionable improvements",
    )
    strategic_initiatives: list[str] = Field(
        description="Long-term strategic improvements",
    )


class ReportSummaryOutput(BaseModel):
    """LLM output for the final report summary."""

    executive_summary: str = Field(
        description="Executive summary of SOC performance",
    )
    overall_score: float = Field(
        description="Overall SOC maturity score 0-100",
    )
    top_strengths: list[str] = Field(
        description="Top 3 SOC strengths",
    )
    top_weaknesses: list[str] = Field(
        description="Top 3 areas needing improvement",
    )


# --------------- System prompts ---------------


SYSTEM_PERFORMANCE_ASSESSMENT = """\
You are an expert SOC performance analyst. Given raw SOC \
metrics across detection, response, prevention, coverage, \
and efficiency categories, assess the performance of each \
category.

For each category provide:
1. The trend direction (improving/stable/declining/volatile)
2. A concise assessment of current performance
3. Contributing factors — what is driving the trend

Consider cross-category dependencies. For example, poor \
detection coverage often degrades response metrics because \
analysts waste time on false positives."""


SYSTEM_BOTTLENECK_DETECTION = """\
You are a SOC operations bottleneck analyst. Given \
performance analyses across all SOC metric categories, \
identify workflow bottlenecks that are degrading overall \
SOC effectiveness.

Focus on:
1. Alert fatigue — excessive volume crushing analyst capacity
2. Triage delays — slow classification increasing MTTR
3. Tooling gaps — missing automation causing manual toil
4. Coverage blind spots — unmonitored attack surfaces
5. Escalation friction — slow hand-offs between tiers
6. Knowledge silos — critical context trapped in individuals

Rank by impact score (0-1) and identify root causes."""


SYSTEM_BENCHMARK_COMPARISON = """\
You are a SOC benchmarking specialist with deep knowledge \
of industry standards from SANS, Ponemon, Verizon DBIR, \
and Gartner SOC maturity models.

Compare the SOC metrics against industry benchmarks:
- MTTD: industry median ~24h, top quartile <4h
- MTTR: industry median ~73h, top quartile <12h
- Alert volume: 500-10K/day typical, >10K indicates tuning need
- False positive rate: 40-60% typical, <20% is excellent
- Analyst utilization: 60-80% healthy, >90% burnout risk
- Coverage ratio: 70% typical, >90% mature SOC

Provide percentile rank and specific gaps to close."""


SYSTEM_RECOMMENDATIONS = """\
You are a SOC transformation advisor generating \
actionable improvement recommendations. Given the \
bottlenecks, benchmark gaps, and performance trends, \
recommend specific improvements.

Prioritize recommendations by:
1. Impact — how much will this improve key metrics?
2. Effort — quick wins first, then strategic initiatives
3. Risk — avoid recommendations that could create gaps

Each recommendation must have concrete implementation \
steps, expected impact on specific metrics, and effort \
estimate (low/medium/high).

Categories:
- Automation (SOAR playbooks, auto-triage, enrichment)
- Tuning (detection rules, thresholds, alert dedup)
- Process (runbooks, escalation, shift coverage)
- Tooling (new capabilities, integrations)
- People (training, hiring, tier restructuring)"""


SYSTEM_REPORT_SUMMARY = """\
You are writing an executive-level SOC performance report \
summary. Synthesize the performance analyses, bottlenecks, \
benchmarks, and recommendations into a clear, actionable \
executive summary.

The summary should:
1. Lead with the overall SOC maturity score (0-100)
2. Highlight top 3 strengths and top 3 weaknesses
3. Quantify the impact of recommended improvements
4. Be concise — 3-5 paragraphs maximum
5. Use concrete numbers, not vague language"""
