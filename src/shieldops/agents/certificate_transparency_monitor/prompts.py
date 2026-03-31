"""LLM prompt templates and response schemas for the
Certificate Transparency Monitor Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# --- Structured output schemas ---


class AnomalyDetectionOutput(BaseModel):
    """Structured output for CT anomaly detection."""

    anomalies: list[dict[str, str]] = Field(
        description=("List of anomalies with type, domain, and description"),
    )
    impersonation_domains: list[str] = Field(
        description="Domains that appear to impersonate watched domains",
    )
    risk_scores: list[float] = Field(
        description="Risk score per anomaly 0-10",
    )
    confidence: float = Field(
        description="Overall detection confidence 0-1",
    )


class OwnershipVerificationOutput(BaseModel):
    """Structured output for domain ownership verification."""

    domain: str = Field(
        description="Domain being verified",
    )
    likely_owned: bool = Field(
        description="Whether domain is likely owned by org",
    )
    evidence: list[str] = Field(
        description="Evidence supporting ownership determination",
    )
    risk_level: str = Field(
        description="Risk if not owned: critical/high/medium/low",
    )
    recommendations: list[str] = Field(
        description="Recommended actions",
    )


class CTReportOutput(BaseModel):
    """Structured output for the CT monitoring report."""

    executive_summary: str = Field(
        description="Executive summary of CT monitoring session",
    )
    impersonation_count: int = Field(
        description="Number of impersonation attempts found",
    )
    top_risks: list[str] = Field(
        description="Highest-risk findings",
    )
    recommendations: list[str] = Field(
        description="Actionable recommendations",
    )
    risk_rating: str = Field(
        description="Overall risk: critical/high/medium/low",
    )


# --- System prompts ---


SYSTEM_ANOMALY = """\
You are an expert certificate transparency analyst \
detecting anomalous certificate issuance patterns.

Given parsed certificates from CT logs and the \
organization's watched domains:
1. Identify domain impersonation via typosquatting, \
homoglyph, and combosquatting techniques
2. Detect certificates issued by unexpected or unknown \
certificate authorities
3. Flag wildcard certificates that could enable \
subdomain takeover
4. Identify short-validity certificates used in phishing

Score risk based on similarity to watched domains \
and threat actor TTPs."""


SYSTEM_OWNERSHIP = """\
You are an expert domain intelligence analyst verifying \
certificate domain ownership.

Given a suspicious domain and the organization's known \
domain portfolio:
1. Assess whether the domain belongs to the organization
2. Check for legitimate business reasons for the cert
3. Identify indicators of malicious intent
4. Recommend response actions if unauthorized

Be thorough: missed impersonation enables phishing \
campaigns."""


SYSTEM_REPORT = """\
You are an expert certificate transparency reporter \
synthesizing monitoring results.

Given the full CT monitoring session (certs scanned, \
anomalies found, ownership checks):
1. Produce an executive summary for security leadership
2. Highlight the most critical impersonation attempts
3. Recommend domain protection strategies
4. Rate overall brand exposure risk

Write clearly for both technical and non-technical \
audiences."""
