"""Security Posture Scorer Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ScoreInsight(BaseModel):
    """Structured output from posture score analysis."""

    summary: str = Field(
        description="Brief posture scoring overview",
    )
    weak_categories: list[str] = Field(
        description="Categories needing improvement",
    )
    strengths: list[str] = Field(
        description="Strong security areas",
    )


class BenchmarkInsight(BaseModel):
    """Structured output from benchmark comparison."""

    summary: str = Field(
        description="Benchmark comparison overview",
    )
    below_average: list[str] = Field(
        description="Areas below industry average",
    )
    recommendations: list[str] = Field(
        description="Improvement recommendations",
    )


class TrendInsight(BaseModel):
    """Structured output from trend analysis."""

    summary: str = Field(
        description="Trend analysis overview",
    )
    improving_areas: list[str] = Field(
        description="Areas showing improvement",
    )
    declining_areas: list[str] = Field(
        description="Areas showing decline",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of security posture",
    )
    key_findings: list[str] = Field(
        description="Key findings for leadership",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a security posture analyst reviewing "
    "multi-source scoring data.\n"
    "1. Identify weak scoring categories\n"
    "2. Compare against CIS benchmarks\n"
    "3. Detect scoring trends and anomalies\n"
    "4. Prioritize remediation by impact"
)

SYSTEM_REPORT = (
    "You are a security posture advisor generating an "
    "executive posture scoring report.\n"
    "1. Summarize overall posture with tier rating\n"
    "2. Highlight categories below industry average\n"
    "3. Show score trends and forecasts\n"
    "4. Recommend priority improvements"
)
