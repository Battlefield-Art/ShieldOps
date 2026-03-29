"""Phishing Email Analyzer Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class PhishingContentOutput(BaseModel):
    """LLM output for phishing content analysis."""

    summary: str = Field(description="Brief phishing analysis summary")
    is_phishing: bool = Field(description="Whether the email is phishing")
    confidence: float = Field(description="Confidence score 0-1")
    indicators: list[str] = Field(description="Phishing indicators found")
    brand_impersonated: str = Field(description="Brand being impersonated if any")
    urgency_score: float = Field(description="Urgency language score 0-1")


class URLRiskOutput(BaseModel):
    """LLM output for URL risk assessment."""

    summary: str = Field(description="Brief URL risk summary")
    risk_level: str = Field(description="Risk: critical, high, medium, low, safe")
    malicious_urls: list[str] = Field(description="URLs identified as malicious")
    credential_harvesting: bool = Field(description="Whether URLs harvest credentials")
    recommendations: list[str] = Field(description="Recommended actions")


SYSTEM_PHISHING_CONTENT = (
    "You are a phishing analyst examining an email "
    "for social engineering indicators.\n"
    "Given the following email content:\n"
    "1. Analyze subject and body for urgency "
    "language (act now, expire, suspend, verify)\n"
    "2. Check for brand impersonation — logos, "
    "company names, official-looking templates\n"
    "3. Identify credential harvesting attempts "
    "(login links, verify account, update payment)\n"
    "4. Check for display name spoofing vs actual "
    "sender domain\n"
    "5. Score overall phishing likelihood and "
    "provide reasoning"
)

SYSTEM_URL_RISK = (
    "You are a URL threat analyst evaluating links "
    "extracted from suspected phishing emails.\n"
    "Given the following URL analysis data:\n"
    "1. Check for URL shorteners hiding true "
    "destinations\n"
    "2. Analyze domains for typosquatting and "
    "homograph attacks\n"
    "3. Check redirect chains for suspicious hops\n"
    "4. Identify login pages and credential "
    "harvesting forms\n"
    "5. Evaluate SSL certificates and domain age"
)
