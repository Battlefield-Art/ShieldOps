"""LLM prompt templates and response schemas for the
SIEM Rule Optimizer Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class RuleCollectionOutput(BaseModel):
    """Structured output for rule collection analysis."""

    total_rules: int = Field(
        description="Total detection rules collected",
    )
    categories: list[str] = Field(
        description="Rule categories found",
    )
    risk_areas: list[str] = Field(
        description="Rules needing immediate attention",
    )
    summary: str = Field(
        description="Collection summary",
    )


class PerformanceAnalysisOutput(BaseModel):
    """Structured output for performance analysis."""

    noisy_rules: list[str] = Field(
        description="Rules with excessive false positives",
    )
    underperforming_rules: list[str] = Field(
        description="Rules with low detection rates",
    )
    avg_precision: float = Field(
        description="Average precision across all rules",
    )
    recommendations: list[str] = Field(
        description="Performance improvement recommendations",
    )


class OverlapDetectionOutput(BaseModel):
    """Structured output for overlap detection."""

    overlap_pairs: int = Field(
        description="Number of overlapping rule pairs",
    )
    redundant_rules: list[str] = Field(
        description="Rules that can be consolidated",
    )
    alert_savings: int = Field(
        description="Estimated alert reduction per day",
    )
    consolidation_plan: str = Field(
        description="Plan for rule consolidation",
    )


class OptimizationReportOutput(BaseModel):
    """Structured output for optimization report."""

    executive_summary: str = Field(
        description="Executive summary of optimizations",
    )
    rules_optimized: int = Field(
        description="Rules with tuning recommendations",
    )
    fp_reduction_pct: float = Field(
        description="Expected false positive reduction %",
    )
    recommendations: list[str] = Field(
        description="Prioritized action items",
    )
    risk_assessment: str = Field(
        description="Risk of implementing changes",
    )


# --- System prompts ---


SYSTEM_COLLECT = """\
You are an expert SIEM detection engineer analyzing \
a rule inventory for optimization opportunities.

Given the SIEM platform and rule filters:
1. Categorize rules by detection logic type
2. Identify rules with outdated or overly broad patterns
3. Flag rules lacking MITRE ATT&CK mapping
4. Highlight disabled or abandoned rules for cleanup

Focus on detection coverage gaps and alert fatigue."""


SYSTEM_ANALYZE = """\
You are an expert SIEM performance analyst evaluating \
detection rule effectiveness.

Given rule performance metrics over the time range:
1. Identify noisy rules with high false positive rates
2. Find underperforming rules with poor recall
3. Calculate precision/recall/F1 for each rule
4. Recommend rules for tuning, consolidation, or retirement

Prioritize analyst time savings and detection quality."""


SYSTEM_OVERLAP = """\
You are an expert detection engineer identifying \
overlapping and redundant SIEM rules.

Given detection rules and their alert patterns:
1. Detect rules triggering on the same events
2. Quantify overlap percentage between rule pairs
3. Recommend consolidation strategies
4. Estimate alert volume reduction from deduplication

Preserve detection coverage while reducing noise."""


SYSTEM_REPORT = """\
You are an expert SIEM optimization reporter synthesizing \
rule tuning results.

Given all analysis, overlaps, and tuning suggestions:
1. Produce an executive summary for SOC leadership
2. Prioritize tuning actions by alert reduction impact
3. Assess risk of false negative increase per change
4. Provide a phased implementation roadmap

Balance noise reduction with detection fidelity."""
