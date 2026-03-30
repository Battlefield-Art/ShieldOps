"""API Gateway Security Agent — LLM prompt templates and schemas."""

from pydantic import BaseModel, Field

# -------------------------------------------------------------------
# Structured output schemas
# -------------------------------------------------------------------


class AuthAnalysisOutput(BaseModel):
    """LLM output for authentication analysis."""

    summary: str = Field(
        description="Brief summary of auth posture",
    )
    weak_auth_count: int = Field(
        description="Endpoints with weak authentication",
    )
    risk_level: str = Field(
        description="Overall auth risk: low/medium/high/critical",
    )
    findings: list[str] = Field(
        description="Key authentication weaknesses found",
    )
    hardening_steps: list[str] = Field(
        description="Prioritized auth hardening steps",
    )


class EndpointScanOutput(BaseModel):
    """LLM output for endpoint input validation scan."""

    summary: str = Field(
        description="Brief summary of scan findings",
    )
    vulnerable_count: int = Field(
        description="Endpoints with validation gaps",
    )
    risk_level: str = Field(
        description="Overall risk: low/medium/high/critical",
    )
    findings: list[str] = Field(
        description="Key input validation and config issues",
    )
    remediation_priorities: list[str] = Field(
        description="Ordered remediation steps",
    )


class AbuseAnalysisOutput(BaseModel):
    """LLM output for API abuse pattern analysis."""

    summary: str = Field(
        description="Brief summary of abuse patterns",
    )
    abuse_count: int = Field(
        description="Confirmed abuse incidents",
    )
    threat_level: str = Field(
        description="Threat level: none/low/medium/high/critical",
    )
    patterns: list[str] = Field(
        description="Identified abuse patterns and TTPs",
    )
    blocking_actions: list[str] = Field(
        description="Recommended blocking/mitigation actions",
    )


class PolicyRecommendationOutput(BaseModel):
    """LLM output for policy enforcement decisions."""

    summary: str = Field(
        description="Summary of enforcement actions taken",
    )
    enforced_count: int = Field(
        description="Number of policies enforced",
    )
    new_rules: list[str] = Field(
        description="New gateway rules recommended",
    )
    confidence: float = Field(
        description="Confidence in decisions 0.0-1.0",
    )


class GatewaySecurityReportOutput(BaseModel):
    """LLM output for the final gateway security report."""

    executive_summary: str = Field(
        description="Executive summary of gateway posture",
    )
    risk_score: float = Field(
        description="Overall risk score 0.0-10.0",
    )
    top_risks: list[str] = Field(
        description="Top 5 risks requiring attention",
    )
    recommendations: list[str] = Field(
        description="Prioritized security recommendations",
    )
    compliance_gaps: list[str] = Field(
        description="Compliance gaps (OWASP, PCI-DSS, SOC 2)",
    )


# -------------------------------------------------------------------
# System prompts
# -------------------------------------------------------------------

SYSTEM_AUTH_ANALYSIS = (
    "You are an API gateway security analyst specializing "
    "in authentication and authorization.\n"
    "Analyze authentication configurations across API "
    "gateway endpoints:\n"
    "1. Identify endpoints with no authentication or weak "
    "auth (basic auth, static API keys without rotation)\n"
    "2. Check OAuth2 scopes — are they properly enforced "
    "and least-privilege?\n"
    "3. Verify JWT configurations — algorithm, expiry, "
    "issuer validation, audience checks\n"
    "4. Assess mTLS adoption for service-to-service calls\n"
    "5. Check for missing MFA on admin endpoints\n"
    "6. Identify token leakage risks (tokens in URLs/logs)\n"
    "Rate each finding by risk and provide hardening steps."
)

SYSTEM_ENDPOINT_SCAN = (
    "You are an API gateway configuration auditor.\n"
    "Scan API gateway endpoint configurations for gaps:\n"
    "1. Input validation — missing request schema, "
    "unbounded parameters, no content-type enforcement\n"
    "2. Rate limiting — missing or overly permissive "
    "limits on sensitive endpoints\n"
    "3. CORS policy — overly permissive origins, "
    "credentials allowed with wildcards\n"
    "4. Security headers — missing HSTS, CSP, "
    "X-Frame-Options, X-Content-Type-Options\n"
    "5. TLS configuration — outdated versions, weak "
    "cipher suites, missing certificate pinning\n"
    "6. Response filtering — sensitive data in error "
    "messages or response bodies\n"
    "Prioritize findings by exploitability and impact."
)

SYSTEM_ABUSE_DETECTION = (
    "You are an API gateway traffic analyst specializing "
    "in abuse detection.\n"
    "Analyze traffic patterns to detect API abuse:\n"
    "1. Credential stuffing — high-volume auth with varied "
    "credentials from few IPs\n"
    "2. API scraping — systematic enumeration of list "
    "endpoints with pagination abuse\n"
    "3. Rate limit bypass — distributed requests staying "
    "just below per-IP thresholds\n"
    "4. Injection probing — elevated error rates with "
    "injection payloads in parameters\n"
    "5. Bot activity — automated traffic, missing or "
    "uniform user agents\n"
    "6. Resource exhaustion — slow POST, large payload "
    "uploads, connection hoarding\n"
    "Correlate source IPs, timing, and payloads to "
    "identify coordinated campaigns."
)

SYSTEM_POLICY_ENFORCEMENT = (
    "You are an API gateway policy engineer.\n"
    "Based on auth gaps, endpoint vulnerabilities, and "
    "abuse patterns, determine enforcement actions:\n"
    "1. Rate limiting — per-endpoint, per-client, and "
    "global thresholds\n"
    "2. WAF rules — block injection, malformed requests, "
    "known bad payloads\n"
    "3. Auth upgrades — require stronger auth on sensitive "
    "endpoints (OAuth2/mTLS over API keys)\n"
    "4. IP reputation blocking — block confirmed abuse "
    "sources, apply geofencing\n"
    "5. Input schema enforcement — deploy OpenAPI schema "
    "validation at the gateway\n"
    "6. Response sanitization — strip internal details "
    "from error responses\n"
    "Balance security with availability. Minimize false "
    "positives."
)

SYSTEM_GATEWAY_REPORT = (
    "You are a senior API security architect preparing an "
    "executive report on gateway security posture.\n"
    "Summarize the assessment including:\n"
    "1. Overall gateway security score (0-10)\n"
    "2. Authentication posture across all endpoints\n"
    "3. Input validation and configuration gaps\n"
    "4. Active abuse patterns and threat level\n"
    "5. Policy enforcement effectiveness\n"
    "6. Compliance alignment (OWASP, PCI-DSS, SOC 2)\n"
    "7. Prioritized remediation roadmap with quick wins\n"
    "Target audience: CISO and platform engineering leads."
)
