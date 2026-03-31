"""DNS Firewall Controller Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class DomainInsight(BaseModel):
    """Structured output from domain analysis."""

    summary: str = Field(
        description="Brief domain analysis overview",
    )
    suspicious_domains: list[str] = Field(
        description="Domains flagged as suspicious",
    )
    dga_candidates: list[str] = Field(
        description="Likely DGA-generated domains",
    )


class TunnelingInsight(BaseModel):
    """Structured output from tunneling detection."""

    summary: str = Field(
        description="DNS tunneling detection overview",
    )
    tunneling_sources: list[str] = Field(
        description="Source IPs performing tunneling",
    )
    exfil_estimates: list[str] = Field(
        description="Estimated data exfiltration volumes",
    )


class PolicyInsight(BaseModel):
    """Structured output from policy enforcement."""

    summary: str = Field(
        description="Policy enforcement overview",
    )
    high_risk_blocks: list[str] = Field(
        description="High-risk domains blocked",
    )
    recommendations: list[str] = Field(
        description="Policy improvement recommendations",
    )


class ReportInsight(BaseModel):
    """Structured output for final report."""

    summary: str = Field(
        description="Executive summary of DNS firewall activity",
    )
    key_findings: list[str] = Field(
        description="Key findings for security team",
    )
    next_steps: list[str] = Field(
        description="Recommended next steps",
    )


SYSTEM_ANALYZE = (
    "You are a DNS firewall analyst reviewing "
    "domain queries and reputation data.\n"
    "1. Identify domains matching DGA patterns\n"
    "2. Flag newly registered or suspicious domains\n"
    "3. Detect potential DNS tunneling activity\n"
    "4. Recommend sinkhole or block actions"
)

SYSTEM_REPORT = (
    "You are a DNS security advisor generating an "
    "executive DNS firewall report.\n"
    "1. Summarize blocked domains by category\n"
    "2. Highlight tunneling detection results\n"
    "3. Quantify policy enforcement effectiveness\n"
    "4. Recommend DNS security improvements"
)
