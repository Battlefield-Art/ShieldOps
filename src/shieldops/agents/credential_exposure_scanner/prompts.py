"""Credential Exposure Scanner Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class ScanInsight(BaseModel):
    """Structured output from credential scan analysis."""

    summary: str = Field(
        description="Brief credential exposure overview",
    )
    high_risk_sources: list[str] = Field(
        description="Sources with most credential leaks",
    )
    patterns_detected: list[str] = Field(
        description="Common exposure patterns found",
    )


class ClassificationInsight(BaseModel):
    """Structured output from credential classification."""

    summary: str = Field(
        description="Credential classification overview",
    )
    active_credentials: list[str] = Field(
        description="Active credentials requiring rotation",
    )
    provider_breakdown: list[str] = Field(
        description="Credentials grouped by provider",
    )


class ExposureInsight(BaseModel):
    """Structured output from exposure assessment."""

    summary: str = Field(
        description="Exposure severity overview",
    )
    critical_exposures: list[str] = Field(
        description="Critical exposure findings",
    )
    recommendations: list[str] = Field(
        description="Immediate remediation steps",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of credential exposure scan",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_SCAN = (
    "You are a credential exposure analyst reviewing "
    "scan results from multiple sources.\n"
    "1. Identify high-entropy strings matching credential patterns\n"
    "2. Detect API keys, tokens, and secrets in code/pastes\n"
    "3. Assess exposure scope and time window\n"
    "4. Prioritize by blast radius and active status"
)

SYSTEM_REPORT = (
    "You are a credential security advisor generating an "
    "executive exposure report.\n"
    "1. Summarize exposed credentials by type and severity\n"
    "2. Highlight active credentials requiring immediate rotation\n"
    "3. Quantify data-at-risk for each exposure\n"
    "4. Recommend credential hygiene improvements"
)
