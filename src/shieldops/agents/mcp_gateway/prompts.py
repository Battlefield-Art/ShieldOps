"""LLM prompt templates and response schemas for the MCP Gateway Agent."""

from __future__ import annotations

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Response schemas for structured LLM output
# ---------------------------------------------------------------------------


class SecurityAssessmentResult(BaseModel):
    """Structured output from LLM security assessment of MCP servers."""

    summary: str = Field(
        description="Brief summary of the security posture across all servers",
    )
    critical_servers: list[str] = Field(
        description="Server IDs that require immediate remediation",
    )
    missing_controls: list[str] = Field(
        description="Security controls missing across the fleet",
    )
    god_key_indicators: list[str] = Field(
        description="Indicators of God Key patterns detected",
    )
    risk_level: str = Field(
        description="Overall risk: low, medium, high, critical",
    )


class PolicyRecommendationResult(BaseModel):
    """Structured output for gateway policy recommendations."""

    policies: list[str] = Field(
        description="Recommended policies to enforce on the gateway",
    )
    enforcement_actions: list[str] = Field(
        description="Concrete enforcement actions per policy",
    )
    rate_limit_rules: list[str] = Field(
        description="Rate limiting rules for high-risk servers",
    )
    estimated_risk_reduction: str = Field(
        description="Estimated risk reduction if all policies are applied",
    )


class AbuseDetectionResult(BaseModel):
    """Structured output from LLM abuse pattern analysis."""

    anomalies_confirmed: list[str] = Field(
        description="Anomalies confirmed as likely abuse",
    )
    false_positives: list[str] = Field(
        description="Anomalies likely to be false positives",
    )
    recommended_blocks: list[str] = Field(
        description="Caller/tool combinations to block immediately",
    )
    summary: str = Field(
        description="Brief summary of abuse detection findings",
    )


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

SYSTEM_SECURITY_ASSESSMENT = """\
You are an expert MCP gateway security assessor. Your job is to evaluate \
MCP server profiles for security risks before allowing traffic through \
the gateway proxy.

Analyze each server profile and identify:
1. Missing or weak authentication (no OAuth2, plaintext API keys)
2. God Key patterns — single credentials granting write access to >3 \
downstream systems
3. Missing TLS / transport encryption
4. Overly broad tool permission scopes
5. Servers without rate limiting configured

Classify each server as CRITICAL, HIGH, MEDIUM, LOW, or SECURE. \
Flag any server that should be blocked at the gateway until remediated."""

SYSTEM_POLICY_ENFORCEMENT = """\
You are an expert generating gateway enforcement policies for MCP server \
ecosystems. Given the security assessments and server profiles, generate \
specific, implementable gateway rules:

1. OAuth 2.0 requirements — which servers need token validation
2. RBAC/ABAC rules — tool-level access by role/attribute
3. Rate limiting — per-server, per-tool, per-caller thresholds
4. Audit logging — which tool calls require full payload capture
5. Transport security — TLS version requirements, certificate pinning

Each policy must be enforceable at the gateway proxy layer. \
Prioritize policies by risk reduction impact."""

SYSTEM_ABUSE_DETECTION = """\
You are an expert analyzing MCP gateway traffic for abuse patterns. \
Given traffic anomalies detected by the monitoring system, determine:

1. Which anomalies are genuine abuse (credential stuffing, data exfil, \
tool hammering)
2. Which are likely false positives (legitimate burst traffic, batch jobs)
3. Which callers/tools should be blocked immediately
4. Recommended rate limit adjustments

Consider that MCP tool calls can be chained — a single compromised agent \
can invoke many tools rapidly. Look for lateral movement patterns \
and privilege escalation via tool chaining."""
