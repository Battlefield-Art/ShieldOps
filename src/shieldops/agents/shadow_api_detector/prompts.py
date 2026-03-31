"""Shadow API Detector Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class TrafficInsight(BaseModel):
    """Structured output from API traffic analysis."""

    summary: str = Field(
        description="Brief API traffic overview",
    )
    anomalies: list[str] = Field(
        description="Detected traffic anomalies",
    )
    undocumented_patterns: list[str] = Field(
        description="Patterns suggesting undocumented APIs",
    )


class ShadowInsight(BaseModel):
    """Structured output from shadow API detection."""

    summary: str = Field(
        description="Shadow API detection overview",
    )
    critical_shadows: list[str] = Field(
        description="Critical shadow APIs found",
    )
    risk_vectors: list[str] = Field(
        description="Identified risk vectors",
    )


class RiskInsight(BaseModel):
    """Structured output from risk classification."""

    summary: str = Field(
        description="Risk classification overview",
    )
    high_risk_apis: list[str] = Field(
        description="High-risk shadow APIs",
    )
    recommendations: list[str] = Field(
        description="Remediation recommendations",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of shadow API analysis",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are an API security analyst reviewing "
    "traffic patterns for shadow APIs.\n"
    "1. Identify undocumented endpoints from traffic\n"
    "2. Flag APIs missing authentication\n"
    "3. Detect data exposure through unprotected endpoints\n"
    "4. Spot deprecated APIs still receiving traffic"
)

SYSTEM_REPORT = (
    "You are an API security advisor generating an "
    "executive shadow API discovery report.\n"
    "1. Summarize shadow APIs by risk and category\n"
    "2. Highlight APIs requiring immediate attention\n"
    "3. Quantify the scope of undocumented API surface\n"
    "4. Recommend API governance improvements"
)
