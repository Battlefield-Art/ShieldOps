"""Asset Exposure Scorer Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class FingerprintInsight(BaseModel):
    """Structured output from service fingerprinting."""

    summary: str = Field(
        description="Brief service fingerprinting overview",
    )
    risky_services: list[str] = Field(
        description="Services with high-risk configurations",
    )
    outdated_versions: list[str] = Field(
        description="Services running outdated versions",
    )


class VulnInsight(BaseModel):
    """Structured output from vulnerability checks."""

    summary: str = Field(
        description="Vulnerability assessment overview",
    )
    critical_vulns: list[str] = Field(
        description="Critical vulnerabilities found",
    )
    attack_vectors: list[str] = Field(
        description="Identified attack vectors",
    )


class ScoreInsight(BaseModel):
    """Structured output from exposure scoring."""

    summary: str = Field(
        description="Exposure scoring overview",
    )
    highest_risk_assets: list[str] = Field(
        description="Assets with highest exposure",
    )
    recommendations: list[str] = Field(
        description="Risk reduction recommendations",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of exposure assessment",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are an external attack surface analyst reviewing "
    "internet-facing assets.\n"
    "1. Identify high-risk service configurations\n"
    "2. Flag assets with known vulnerabilities\n"
    "3. Assess TLS and certificate health\n"
    "4. Evaluate exposure relative to business criticality"
)

SYSTEM_REPORT = (
    "You are a security advisor generating an "
    "asset exposure assessment report.\n"
    "1. Summarize exposure by asset type and severity\n"
    "2. Highlight critical risks requiring immediate action\n"
    "3. Quantify the external attack surface\n"
    "4. Recommend exposure reduction strategies"
)
