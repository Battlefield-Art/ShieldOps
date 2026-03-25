"""API Security Agent — LLM prompt templates and structured output schemas."""

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Structured output schemas
# ---------------------------------------------------------------------------


class VulnAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted vulnerability analysis."""

    summary: str = Field(description="Brief summary of vulnerability findings")
    critical_count: int = Field(description="Number of critical/high vulnerabilities")
    risk_level: str = Field(description="Overall risk level: low, medium, high, critical")
    findings: list[str] = Field(description="Key vulnerability findings with OWASP references")
    remediation_priorities: list[str] = Field(description="Prioritized remediation steps")


class AbuseDetectionOutput(BaseModel):
    """Structured output from LLM-assisted abuse detection."""

    summary: str = Field(description="Brief summary of detected abuse patterns")
    abuse_count: int = Field(description="Number of confirmed abuse incidents")
    threat_level: str = Field(description="Threat level: none, low, medium, high, critical")
    patterns: list[str] = Field(description="Identified abuse patterns")
    blocking_recommendations: list[str] = Field(
        description="Recommended blocking/mitigation actions"
    )


class PolicyOutput(BaseModel):
    """Structured output from LLM-assisted policy enforcement decisions."""

    summary: str = Field(description="Brief summary of enforcement actions taken")
    enforced_count: int = Field(description="Number of policies enforced")
    new_rules: list[str] = Field(description="New rules to add based on findings")
    confidence: float = Field(description="Confidence in enforcement decisions 0.0-1.0")


class SecuritySummaryOutput(BaseModel):
    """Structured output for the final security summary report."""

    executive_summary: str = Field(description="Executive summary of API security posture")
    risk_score: float = Field(description="Overall risk score 0.0-10.0")
    top_risks: list[str] = Field(description="Top 5 risks requiring attention")
    recommendations: list[str] = Field(description="Prioritized security recommendations")
    compliance_gaps: list[str] = Field(
        description="Compliance gaps identified (OWASP, PCI-DSS, etc.)"
    )


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_VULN_ANALYSIS = (
    "You are an API security analyst specializing in OWASP API Security Top 10.\n"
    "Analyze the discovered API endpoints and their traffic patterns to identify "
    "vulnerabilities.\n"
    "For each endpoint:\n"
    "1. Check for Broken Object Level Authorization (BOLA) — sequential IDs, "
    "missing ownership checks\n"
    "2. Check for Broken Authentication — weak tokens, missing rate limits on "
    "auth endpoints\n"
    "3. Check for Excessive Data Exposure — responses returning more fields than "
    "the client needs\n"
    "4. Check for Lack of Resources & Rate Limiting — no throttling on expensive "
    "operations\n"
    "5. Check for Broken Function Level Authorization — admin endpoints accessible "
    "to regular users\n"
    "6. Check for Mass Assignment — accepting unexpected fields in request bodies\n"
    "7. Check for Security Misconfiguration — verbose errors, missing CORS, "
    "debug enabled\n"
    "8. Check for Injection — SQL, NoSQL, command injection via API parameters\n"
    "9. Check for Improper Assets Management — deprecated or undocumented endpoints\n"
    "10. Check for Server-Side Request Forgery — URL parameters that trigger "
    "server-side requests\n"
    "Rate each finding by severity and confidence. Provide CWE references."
)

SYSTEM_ABUSE_DETECTION = (
    "You are a security analyst specializing in API abuse detection.\n"
    "Analyze traffic patterns across API endpoints to identify abuse:\n"
    "1. Credential stuffing — high-volume auth attempts with varied credentials\n"
    "2. Scraping — systematic enumeration of list/search endpoints\n"
    "3. Enumeration — sequential probing of resource IDs\n"
    "4. Rate abuse — sustained traffic exceeding normal usage patterns\n"
    "5. Data harvesting — bulk export via pagination or filter abuse\n"
    "6. Brute force — repeated attempts against auth or restricted endpoints\n"
    "Correlate source IPs, user agents, and timing patterns. Flag coordinated "
    "attacks from distributed sources."
)

SYSTEM_POLICY_ENFORCEMENT = (
    "You are an API security policy engineer.\n"
    "Based on detected vulnerabilities and abuse patterns, determine which "
    "enforcement actions to apply:\n"
    "1. Rate limiting — set appropriate thresholds per endpoint and client\n"
    "2. WAF rules — block known attack patterns (injection, SSRF payloads)\n"
    "3. Authentication hardening — require stronger auth on sensitive endpoints\n"
    "4. IP blocking — block confirmed abuse source IPs\n"
    "5. Response filtering — strip excessive data from responses\n"
    "6. Input validation — enforce schema validation on request bodies\n"
    "Balance security with availability. Avoid blocking legitimate traffic."
)

SYSTEM_SECURITY_SUMMARY = (
    "You are a senior API security consultant preparing an executive report.\n"
    "Summarize the API security assessment including:\n"
    "1. Overall security posture score (0-10)\n"
    "2. Top risks ranked by severity and exploitability\n"
    "3. Compliance gaps against OWASP API Top 10, PCI-DSS, SOC 2\n"
    "4. Prioritized remediation roadmap\n"
    "5. Quick wins vs. long-term improvements\n"
    "Be concise and actionable. Target audience is CISO and engineering leads."
)
