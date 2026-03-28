"""LLM prompts and schemas for the Finding Correlator Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CorrelationAnalysisOutput(BaseModel):
    """Structured output for finding correlation."""

    correlation_reason: str = Field(description="Why these findings are related")
    strength: str = Field(description="strong/moderate/weak/none")
    combined_risk: float = Field(description="Combined risk score 0-10")
    attack_narrative: str = Field(description="Attack story connecting findings")


class PrioritizationOutput(BaseModel):
    """Structured output for finding prioritization."""

    priority_rank: int = Field(description="Priority rank (1=highest)")
    risk_score: float = Field(description="Final risk score 0-10")
    recommended_action: str = Field(description="What to do about this finding")
    reasoning: str = Field(description="Why this priority was assigned")


class CorrelatorReportOutput(BaseModel):
    """Structured output for correlator report."""

    executive_summary: str = Field(description="Summary for leadership")
    unique_findings: int = Field(description="Unique findings after dedup")
    duplicates_removed: int = Field(description="Number of duplicates removed")
    top_findings: list[str] = Field(description="Top priority finding titles")
    recommendations: list[str] = Field(description="Actionable recommendations")


SYSTEM_CORRELATE = """\
You are a security finding correlation expert. Given \
two or more findings, determine if they are related.

Consider:
1. Same vulnerability on same/related assets
2. Same attack chain across different vectors
3. Same root cause manifesting differently
4. Same CVE from different scanners

Provide correlation strength and a narrative \
explaining the relationship."""


SYSTEM_PRIORITIZE = """\
You are a risk-based finding prioritizer. Given a \
finding with its context and correlations:

1. Assign a priority rank (1=highest)
2. Calculate a composite risk score (0-10)
3. Recommend a specific remediation action
4. Explain your reasoning

Weight exploitability and business impact highest."""


SYSTEM_REPORT = """\
You are a security analyst summarizing finding \
correlation results.

Given raw findings, deduplication results, and \
correlation groups:
1. Write an executive summary
2. Report deduplication effectiveness
3. Highlight top correlated finding groups
4. Provide prioritized recommendations

Focus on noise reduction and actionable insights."""
