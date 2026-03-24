"""LLM prompt templates and response schemas for the MCP Security Agent."""

from pydantic import BaseModel, Field

# --- Response schemas for structured LLM output ---


class VulnerabilityAssessmentResult(BaseModel):
    """Structured output from LLM vulnerability assessment."""

    summary: str = Field(description="Brief summary of vulnerabilities found")
    vulnerabilities: list[str] = Field(
        description="List of vulnerability descriptions with severity"
    )
    critical_findings: list[str] = Field(description="Findings requiring immediate attention")
    risk_level: str = Field(description="Overall risk: low, medium, high, critical")


class GodKeyAnalysisResult(BaseModel):
    """Structured output from God Key analysis."""

    god_keys_found: list[str] = Field(
        description="Servers identified as God Keys with excessive downstream access"
    )
    blast_radius_summary: str = Field(
        description="Summary of potential blast radius if any God Key is compromised"
    )
    credential_scope_issues: list[str] = Field(description="Credential scope violations found")
    recommendations: list[str] = Field(
        description="Specific remediation recommendations for each God Key"
    )


class PolicyGenerationResult(BaseModel):
    """Structured output for zero-trust policy generation."""

    policies: list[str] = Field(description="Human-readable policy descriptions to enforce")
    enforcement_actions: list[str] = Field(
        description="Concrete enforcement actions (e.g., require_oauth2, block_tool)"
    )
    priority_order: list[str] = Field(description="Policies ordered by implementation priority")
    estimated_risk_reduction: str = Field(
        description="Estimated risk reduction if all policies are applied"
    )


# --- Prompt templates ---

SYSTEM_MCP_SECURITY_AUDIT = """\
You are an expert MCP (Model Context Protocol) security auditor \
analyzing MCP server configurations for security vulnerabilities.

Your task is to analyze the provided MCP server configurations and identify:
1. Misconfigured authentication (missing OAuth2, plaintext tokens, no mTLS)
2. Overly broad tool permissions (tools that can access sensitive data without scoping)
3. Missing transport encryption (stdio over untrusted networks, no TLS)
4. Configuration drift from security baselines
5. Deprecated or vulnerable MCP server versions

Focus on actionable findings with clear severity ratings. \
Consider the MCP specification's security recommendations."""

SYSTEM_GOD_KEY_ANALYSIS = """\
You are an expert analyzing the "God Key" problem in MCP deployments. \
A God Key is a single MCP server credential that grants access to \
many downstream resources — if compromised, the blast radius is catastrophic.

Your task is to:
1. Identify servers acting as God Keys (accessing 5+ downstream resources)
2. Assess the blast radius of each God Key
3. Map credential scope violations (credentials broader than needed)
4. Recommend least-privilege decomposition strategies

IMPORTANT:
- Flag any server with write/admin access to databases, code repos, or cloud IAM
- Consider transitive exposure through agent chains
- Recommend specific credential scoping (e.g., read-only DB, single-bucket S3)"""

SYSTEM_MCP_POLICY_GENERATION = """\
You are an expert generating zero-trust security policies \
for MCP server ecosystems.

Given the discovered servers, vulnerabilities, and God Key risks, \
generate specific, implementable policies:
1. Authentication requirements per server (OAuth2, mTLS, JWT)
2. Tool-level access controls (allowed/blocked tools per agent)
3. Rate limiting and data size caps
4. Transport encryption requirements
5. Audit and monitoring requirements

Policies should follow least-privilege principles. \
Each policy must be actionable and enforceable via the MCP Security Gateway."""
