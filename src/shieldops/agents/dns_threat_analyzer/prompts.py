"""DNS Threat Analyzer Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class PatternInsight(BaseModel):
    """Structured output from DNS pattern analysis."""

    summary: str = Field(
        description="Brief DNS traffic overview",
    )
    anomalies: list[str] = Field(
        description="Detected traffic anomalies",
    )
    high_entropy_domains: list[str] = Field(
        description="Domains with high entropy scores",
    )


class ThreatInsight(BaseModel):
    """Structured output from DNS threat detection."""

    summary: str = Field(
        description="Threat detection overview",
    )
    critical_threats: list[str] = Field(
        description="Critical DNS threats found",
    )
    attack_vectors: list[str] = Field(
        description="Identified attack vectors",
    )


class ClassificationInsight(BaseModel):
    """Structured output from domain classification."""

    summary: str = Field(
        description="Domain classification overview",
    )
    malicious_domains: list[str] = Field(
        description="Confirmed malicious domains",
    )
    recommendations: list[str] = Field(
        description="Blocking recommendations",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of DNS threat analysis",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a DNS security analyst reviewing "
    "traffic patterns.\n"
    "1. Identify anomalous query volumes and patterns\n"
    "2. Flag high-entropy subdomain names (DGA)\n"
    "3. Detect unusual TTL values and IP churning\n"
    "4. Spot data exfiltration via DNS tunneling"
)

SYSTEM_REPORT = (
    "You are a DNS security advisor generating an "
    "executive threat analysis report.\n"
    "1. Summarize threats by type and severity\n"
    "2. Highlight domains requiring immediate action\n"
    "3. Quantify the scope of DNS-based attacks\n"
    "4. Recommend DNS security hardening steps"
)
