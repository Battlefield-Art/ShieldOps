"""LLM prompt templates and response schemas for the Log Analyzer Agent."""

from pydantic import BaseModel, Field


class AnomalyAnalysisOutput(BaseModel):
    """Structured output for LLM-enhanced anomaly analysis."""

    anomaly_type: str = Field(description="Category of anomaly detected")
    description: str = Field(description="Human-readable description of the anomaly")
    severity: str = Field(description="Severity: critical/high/medium/low/info")
    likely_cause: str = Field(description="Most probable root cause")
    recommended_action: str = Field(description="Suggested remediation step")
    confidence: float = Field(description="Confidence in analysis 0-1")


class CorrelationOutput(BaseModel):
    """Structured output for LLM-enhanced event correlation."""

    correlation_type: str = Field(description="Type of correlation found")
    root_cause_hypothesis: str = Field(description="Hypothesis for shared root cause")
    affected_services: list[str] = Field(description="List of affected services")
    confidence: float = Field(description="Confidence in correlation 0-1")
    reasoning: str = Field(description="Explanation of correlation logic")


class ReportOutput(BaseModel):
    """Structured output for final analysis report generation."""

    summary: str = Field(description="Executive summary of log analysis findings")
    key_findings: list[str] = Field(description="Top findings ranked by severity")
    recommendations: list[str] = Field(description="Actionable recommendations")
    risk_level: str = Field(description="Overall risk level: critical/high/medium/low")


SYSTEM_ANOMALY_ANALYSIS = """\
You are an expert log analyst performing anomaly detection.

Given the log patterns and statistical deviations:
1. Classify each anomaly by type (spike, drop, new_pattern, error_burst, latency)
2. Assess severity based on deviation percentage and service criticality
3. Hypothesize the likely root cause

Focus on actionable insights over raw statistics."""


SYSTEM_CORRELATION = """\
You are an expert log analyst correlating anomalous events.

Given multiple anomalies detected across log sources:
1. Identify anomalies that share a common root cause
2. Build a causal chain explaining the propagation
3. Assess confidence in the correlation

Consider temporal proximity, service dependencies, and shared infrastructure."""


SYSTEM_REPORT = """\
You are an expert log analyst generating an executive analysis report.

Given the full analysis context (patterns, anomalies, correlations):
1. Summarize findings in clear, non-technical language
2. Rank findings by business impact
3. Provide actionable recommendations

Be concise — focus on what matters and what to do about it."""
