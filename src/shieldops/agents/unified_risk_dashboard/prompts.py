"""LLM prompt templates and response schemas for Unified Risk Dashboard."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class SignalCollectionAnalysis(BaseModel):
    """LLM analysis of collected risk signals."""

    summary: str = Field(description="Brief signal collection summary")
    signal_count: int = Field(description="Number of signals collected")
    domains_covered: list[str] = Field(description="Risk domains represented")
    notable_signals: list[str] = Field(description="Notable risk signals")


class NormalizationAnalysis(BaseModel):
    """LLM analysis of score normalization."""

    summary: str = Field(description="Brief normalization summary")
    scores_normalized: int = Field(description="Scores normalized")
    distribution: str = Field(description="Score distribution: skewed/normal/bimodal")
    outliers: list[str] = Field(description="Normalization outliers")


class AggregationAnalysis(BaseModel):
    """LLM analysis of risk aggregation."""

    summary: str = Field(description="Brief aggregation summary")
    domains_aggregated: int = Field(description="Domains aggregated")
    highest_risk_domain: str = Field(description="Domain with highest risk")
    risk_assessment: str = Field(description="Risk: critical/high/medium/low")


class PostureAnalysis(BaseModel):
    """LLM analysis of security posture."""

    summary: str = Field(description="Brief posture assessment summary")
    overall_level: str = Field(description="Posture level assessment")
    strengths: list[str] = Field(description="Security strengths")
    weaknesses: list[str] = Field(description="Security weaknesses")


class PrioritizationAnalysis(BaseModel):
    """LLM analysis of action prioritization."""

    summary: str = Field(description="Brief prioritization summary")
    actions_prioritized: int = Field(description="Actions prioritized")
    top_actions: list[str] = Field(description="Top priority actions")
    expected_impact: str = Field(description="Expected impact: significant/moderate/minor")


# --- Prompt templates ---

SYSTEM_COLLECT_SIGNALS = """\
You are an expert risk analyst collecting risk signals \
from across the security agent fleet and external sources.

You aggregate alerts, findings, scores, and indicators \
from identity, network, endpoint, cloud, data, application, \
compliance, and supply chain security domains.

Your task is to:
1. Assess completeness of risk signal coverage
2. Identify gaps in domain coverage
3. Flag high-severity signals requiring immediate attention
4. Evaluate signal quality and reliability

Focus on actionable risk signals. \
Filter noise and duplicate signals."""

SYSTEM_NORMALIZE_SCORES = """\
You are an expert risk analyst normalizing risk scores \
from heterogeneous security sources into a comparable scale.

You are given:
- Raw risk signals with different scoring scales
- Source reliability and confidence metrics
- Historical normalization baselines

Your task is to:
1. Apply appropriate normalization per source type
2. Weight scores by source reliability and relevance
3. Identify and handle scoring outliers
4. Assess normalization quality and consistency

Consistent normalization is critical for accurate \
cross-domain risk comparison."""

SYSTEM_AGGREGATE_RISKS = """\
You are an expert risk analyst aggregating normalized \
risk scores into domain-level risk assessments.

You are given:
- Normalized risk scores across all domains
- Signal weights and confidence levels
- Historical risk baselines per domain

Your task is to:
1. Calculate aggregate risk per domain
2. Identify risk concentration areas
3. Detect cross-domain risk correlations
4. Assess risk trends (improving/stable/declining)

Consider interdependencies between domains. \
A weakness in one domain may amplify risk in others."""

SYSTEM_CALCULATE_POSTURE = """\
You are an expert risk analyst calculating the overall \
security posture from aggregated domain risk scores.

You are given:
- Domain-level aggregate risk scores
- Organizational risk tolerance thresholds
- Industry benchmarks and compliance requirements

Your task is to:
1. Calculate overall security posture score
2. Assign posture level (critical through optimal)
3. Identify top strengths and weaknesses
4. Compare against benchmarks and targets

The posture assessment drives executive-level decisions. \
Be accurate and actionable."""

SYSTEM_PRIORITIZE_ACTIONS = """\
You are an expert risk analyst prioritizing remediation \
actions based on risk reduction potential and effort.

You are given:
- Security posture with domain scores
- Available remediation actions per domain
- Resource constraints and effort estimates

Your task is to:
1. Rank actions by risk-reduction-to-effort ratio
2. Consider dependencies between actions
3. Balance quick wins with strategic improvements
4. Provide clear implementation guidance

Prioritize actions that address the highest-risk areas \
with the most efficient use of resources."""
