"""IT Asset Intelligence Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class AssetDiscoveryInsight(BaseModel):
    """Structured output from LLM-assisted asset discovery."""

    summary: str = Field(description="Brief summary of discovered assets")
    shadow_it_risks: list[str] = Field(description="Potential shadow IT or unmanaged assets")
    coverage_gaps: list[str] = Field(description="Gaps in asset inventory coverage")


class CriticalityInsight(BaseModel):
    """Structured output from LLM-assisted criticality."""

    summary: str = Field(description="Criticality classification overview")
    tier1_assets: list[str] = Field(description="Mission-critical assets requiring top priority")
    dependency_risks: list[str] = Field(description="Assets with risky dependency chains")


class PostureInsight(BaseModel):
    """Structured output from LLM-assisted posture check."""

    summary: str = Field(description="Security posture assessment overview")
    urgent_fixes: list[str] = Field(description="Assets needing immediate remediation")
    compliance_gaps: list[str] = Field(description="Compliance standard violations")


class ThreatInsight(BaseModel):
    """Structured output from LLM-assisted threat correlation."""

    summary: str = Field(description="Threat correlation overview")
    active_campaigns: list[str] = Field(description="Active threat campaigns affecting assets")
    exposure_vectors: list[str] = Field(description="Key exposure vectors to address")


SYSTEM_DISCOVER = (
    "You are an IT asset management specialist analysing "
    "discovered infrastructure assets.\n"
    "1. Identify unmanaged or shadow IT assets\n"
    "2. Flag assets missing endpoint protection\n"
    "3. Assess inventory coverage across categories\n"
    "4. Note assets with stale last-seen timestamps"
)

SYSTEM_CLASSIFY = (
    "You are a business continuity analyst classifying "
    "asset criticality.\n"
    "1. Rank assets by business impact\n"
    "2. Identify single points of failure\n"
    "3. Map dependency chains for critical services\n"
    "4. Flag data-sensitive assets requiring extra controls"
)

SYSTEM_POSTURE = (
    "You are a security posture analyst assessing "
    "asset security health.\n"
    "1. Evaluate patch compliance against baselines\n"
    "2. Identify assets with missing security controls\n"
    "3. Assess encryption and EDR coverage\n"
    "4. Map findings to compliance frameworks"
)

SYSTEM_THREAT = (
    "You are a threat intelligence analyst correlating "
    "assets with active threats.\n"
    "1. Map assets to known threat indicators\n"
    "2. Assess attack surface exposure per asset\n"
    "3. Correlate with MITRE ATT&CK techniques\n"
    "4. Identify assets targeted by active campaigns"
)
