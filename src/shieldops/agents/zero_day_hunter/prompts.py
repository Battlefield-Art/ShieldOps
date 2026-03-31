"""Zero Day Hunter Agent — LLM prompt templates and
structured output schemas."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class ExploitAnalysisOutput(BaseModel):
    """Structured output for exploit analysis."""

    summary: str = Field(
        description="Summary of exploit analysis",
    )
    severity: str = Field(
        description="Severity: critical/high/medium/low",
    )
    attack_vector: str = Field(
        description="Attack vector description",
    )
    exploitability: str = Field(
        description="Exploitability: trivial/moderate/complex",
    )
    mitre_techniques: list[str] = Field(
        description="Mapped MITRE ATT&CK technique IDs",
    )
    recommendations: list[str] = Field(
        description="Immediate mitigation recommendations",
    )


class ExposureAssessmentOutput(BaseModel):
    """Structured output for exposure assessment."""

    summary: str = Field(
        description="Summary of exposure assessment",
    )
    exposed_asset_count: int = Field(
        description="Number of exposed assets",
    )
    internet_facing_count: int = Field(
        description="Internet-facing exposed assets",
    )
    business_impact: str = Field(
        description="Impact: catastrophic/severe/moderate/low",
    )
    priority_assets: list[str] = Field(
        description="Highest-priority assets to patch",
    )
    risk_score: float = Field(
        description="Overall exposure risk 0-10",
    )


class SignatureDevelopmentOutput(BaseModel):
    """Structured output for signature development."""

    summary: str = Field(
        description="Summary of signature development",
    )
    signatures_created: int = Field(
        description="Number of signatures created",
    )
    coverage_estimate: float = Field(
        description="Estimated detection coverage 0-1",
    )
    false_positive_risk: str = Field(
        description="FP risk: low/medium/high",
    )
    deployment_notes: list[str] = Field(
        description="Deployment considerations",
    )


class ZeroDayReportOutput(BaseModel):
    """Structured output for final hunt report."""

    executive_summary: str = Field(
        description="Executive summary of zero-day hunt",
    )
    threat_level: str = Field(
        description="Overall: none, low, medium, high, critical",
    )
    zero_days_tracked: int = Field(
        description="Number of zero-days tracked",
    )
    key_findings: list[str] = Field(
        description="Key findings from the hunt",
    )
    recommendations: list[str] = Field(
        description="Strategic recommendations",
    )
    mitre_coverage: list[str] = Field(
        description="MITRE techniques covered",
    )


# --- System prompts ---

SYSTEM_EXPLOIT_ANALYSIS = """\
You are an expert vulnerability researcher analyzing \
zero-day exploits.

Given threat feed data about a zero-day vulnerability:
1. Classify the exploit type and attack vector
2. Assess exploitability: is a weaponized exploit \
available or trivially reproducible?
3. Map to MITRE ATT&CK techniques for detection
4. Estimate impact scope based on affected products
5. Recommend immediate mitigations before patch \
availability"""

SYSTEM_EXPOSURE_ASSESSMENT = """\
You are an exposure management specialist assessing \
organizational risk from zero-day vulnerabilities.

Given exploit analysis and asset inventory data:
1. Identify all exposed assets running affected products
2. Prioritize internet-facing and crown-jewel assets
3. Assess business impact using asset criticality
4. Compute exposure risk score factoring exploitability
5. Recommend compensating controls until patches arrive"""

SYSTEM_SIGNATURE_DEVELOPMENT = """\
You are a detection engineer developing virtual patches \
and detection signatures for zero-day exploits.

Given exploit analysis and exposure data:
1. Develop IDS/IPS signatures for network detection
2. Create EDR behavioral rules for endpoint detection
3. Design WAF virtual patches for web-facing exposure
4. Estimate detection coverage and false positive risk
5. Plan phased deployment to minimize disruption"""

SYSTEM_REPORT = """\
You are a threat intelligence analyst producing a \
zero-day hunt report for security leadership.

Given the full hunt (feeds, analyses, exposures, \
signatures, mitigations):
1. Produce an executive summary of zero-day posture
2. Highlight the most critical exposures and actions
3. Summarize detection coverage achieved
4. Map findings to MITRE ATT&CK for visibility
5. Recommend strategic improvements to zero-day \
readiness"""
