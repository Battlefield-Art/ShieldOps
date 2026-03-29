"""Email Gateway Analyzer Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class AuthValidationOutput(BaseModel):
    """LLM output for authentication validation."""

    summary: str = Field(description="Brief summary of auth validation findings")
    risk_level: str = Field(description="Risk level: critical, high, medium, low, none")
    misconfigured_domains: list[str] = Field(description="Domains with misconfigured auth records")
    recommendations: list[str] = Field(
        description="Actionable recommendations for auth improvement"
    )


class SpoofingDetectionOutput(BaseModel):
    """LLM output for spoofing detection analysis."""

    summary: str = Field(description="Brief spoofing detection summary")
    threat_level: str = Field(description="Threat level: critical, high, medium, low, none")
    spoofing_indicators: list[str] = Field(description="Indicators of spoofing attempts detected")
    impersonated_domains: list[str] = Field(description="Domains being impersonated")
    mitigation_steps: list[str] = Field(description="Steps to mitigate spoofing risks")


SYSTEM_AUTH_VALIDATION = (
    "You are an email security engineer analyzing "
    "DNS authentication records for email domains.\n"
    "Given the following SPF/DKIM/DMARC records:\n"
    "1. Evaluate SPF — check for overly permissive "
    "mechanisms (+all), missing records, too many "
    "DNS lookups (>10)\n"
    "2. Evaluate DKIM — check key length (>=2048), "
    "selector configuration, signature alignment\n"
    "3. Evaluate DMARC — check policy (reject > "
    "quarantine > none), alignment mode, rua/ruf "
    "reporting\n"
    "4. Check MTA-STS and BIMI adoption\n"
    "5. Provide prioritized recommendations"
)

SYSTEM_SPOOFING_DETECTION = (
    "You are a threat analyst detecting email "
    "spoofing and impersonation attempts.\n"
    "Given the following email header analysis:\n"
    "1. Compare envelope sender vs header sender "
    "for mismatches\n"
    "2. Analyze Received chain for suspicious "
    "relays or forged hops\n"
    "3. Check authentication results for failures\n"
    "4. Identify display name spoofing and "
    "lookalike domains\n"
    "5. Assess threat level and recommend "
    "mitigations"
)
