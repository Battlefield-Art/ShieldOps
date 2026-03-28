"""LLM prompts and schemas for Security Data Lake."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# -----------------------------------------------------------
# Response schemas
# -----------------------------------------------------------


class QueryParseOutput(BaseModel):
    """LLM output for NL query parsing."""

    query_type: str = Field(description=("search, aggregate, trend, correlation, or export"))
    filters: dict[str, Any] = Field(description="Parsed filter conditions")
    time_range_hours: int = Field(description="Time range in hours")
    intent: str = Field(description="User intent summary")


class SourceSelectionOutput(BaseModel):
    """LLM output for source identification."""

    sources: list[str] = Field(description="Data sources to query")
    relevance_scores: dict[str, float] = Field(description="Relevance score per source")
    rationale: str = Field(description="Why these sources selected")


class DataAnalysisOutput(BaseModel):
    """LLM output for data analysis."""

    summary: str = Field(description="Analysis summary")
    patterns: list[str] = Field(description="Patterns found in data")
    anomalies: list[str] = Field(description="Anomalies detected")
    correlations: list[str] = Field(description="Cross-source correlations")
    insights: list[str] = Field(description="Actionable insights")


class DataLakeReportOutput(BaseModel):
    """LLM output for final report."""

    executive_summary: str = Field(description="Executive summary")
    key_findings: list[str] = Field(description="Key findings")
    recommendations: list[str] = Field(description="Recommendations")


# -----------------------------------------------------------
# Prompt templates
# -----------------------------------------------------------

SYSTEM_QUERY_PARSE = """\
You are a security data analyst parsing natural \
language queries into structured data lake queries. \
Extract: query type (search/aggregate/trend/ \
correlation/export), filter conditions, time range, \
and user intent.

Examples:
- "Show me all critical findings from last week" \
-> search, severity=critical, 168h
- "How many alerts per agent in the last 24 hours" \
-> aggregate, group_by=agent, 24h
- "Correlate failed logins with lateral movement" \
-> correlation, sources=[audit_logs, agent_findings]"""

SYSTEM_SOURCE_SELECTION = """\
You are a data routing expert selecting which data \
sources to query based on the parsed query. Available \
sources: agent_findings, agent_metrics, audit_logs, \
scan_results, remediation_records, ticket_data.

Select the most relevant sources and assign relevance \
scores (0-1). Prefer fewer, more relevant sources \
over querying everything."""

SYSTEM_DATA_ANALYSIS = """\
You are a senior security data analyst interpreting \
query results from multiple sources. Identify \
patterns, anomalies, cross-source correlations, and \
actionable insights.

Focus on: threat patterns, coverage gaps, response \
effectiveness, and trending issues."""

SYSTEM_DATA_LAKE_REPORT = """\
You are a security intelligence analyst writing a \
report on data lake query results. Provide an \
executive summary, key findings, and recommendations.

Be concise and actionable. Quantify findings where \
possible."""
