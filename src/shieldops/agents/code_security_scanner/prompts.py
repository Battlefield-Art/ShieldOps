"""Code Security Scanner Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field


class IaCAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted IaC analysis."""

    summary: str = Field(description="Brief summary of IaC security posture")
    critical_misconfigs: int = Field(description="Number of critical misconfigurations found")
    logic_flaws: list[str] = Field(description="Logic-level flaws static analysis missed")
    remediation_notes: list[str] = Field(description="Remediation guidance for top findings")


class DependencyAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted dependency analysis."""

    summary: str = Field(description="Brief dependency risk summary")
    exploitable_count: int = Field(description="CVEs likely exploitable in this context")
    false_positive_ids: list[str] = Field(description="CVE IDs unlikely to be exploitable")
    upgrade_recommendations: list[str] = Field(description="Recommended dependency upgrades")


class CodeAnalysisOutput(BaseModel):
    """Structured output from LLM-assisted code analysis."""

    summary: str = Field(description="Brief application code security summary")
    logic_vulnerabilities: list[str] = Field(description="Logic-level vulns that SAST tools miss")
    ai_specific_risks: list[str] = Field(description="AI-specific risks (prompt injection, etc.)")
    false_positive_ids: list[str] = Field(description="Finding IDs that are false positives")


class PrioritizationOutput(BaseModel):
    """Structured output from LLM-assisted finding prioritization."""

    summary: str = Field(description="Brief prioritization summary")
    top_risk_ids: list[str] = Field(description="Finding IDs representing highest risk")
    exploitable_ids: list[str] = Field(description="Finding IDs confirmed exploitable")
    priority_scores: dict[str, float] = Field(description="Finding ID to priority score mapping")
    risk_narrative: str = Field(description="Overall risk narrative for stakeholders")


SYSTEM_IAC_ANALYSIS = (
    "You are an infrastructure security expert analyzing "
    "IaC templates (Terraform, CloudFormation, K8s YAML).\n"
    "Go beyond static rules to find logic-level flaws:\n"
    "1. Overly permissive IAM policies (wildcards, admin)\n"
    "2. Unencrypted storage, databases, or transit\n"
    "3. Public exposure of internal resources\n"
    "4. Missing logging, monitoring, or audit trails\n"
    "5. Insecure defaults that bypass security controls\n"
    "6. Cross-resource trust chains that create "
    "privilege escalation paths"
)

SYSTEM_DEPENDENCY_ANALYSIS = (
    "You are a software composition analyst evaluating "
    "dependency vulnerabilities.\n"
    "For each CVE:\n"
    "1. Assess exploitability in this application context\n"
    "2. Check if the vulnerable function is actually called\n"
    "3. Determine if network exposure enables exploitation\n"
    "4. Identify transitive dependency chains that amplify risk\n"
    "5. Recommend minimal upgrade paths that fix vulns "
    "without breaking changes"
)

SYSTEM_CODE_ANALYSIS = (
    "You are a senior application security engineer "
    "performing deep code review.\n"
    "Find vulnerabilities that static analysis misses:\n"
    "1. Business logic flaws (authn/authz bypasses, IDOR)\n"
    "2. Race conditions and TOCTOU vulnerabilities\n"
    "3. Injection via complex data flows (second-order)\n"
    "4. Insecure deserialization and type confusion\n"
    "5. AI-SPECIFIC: prompt injection in templates, "
    "insecure RAG configs, unvalidated tool definitions, "
    "agent privilege escalation, LLM output trust issues\n"
    "6. AI-SPECIFIC: missing guardrails on agent actions, "
    "unrestricted tool access, prompt leakage risks"
)

SYSTEM_PRIORITIZATION = (
    "You are a security risk analyst prioritizing findings "
    "for remediation.\n"
    "Combine all scan results (IaC, dependencies, code) and:\n"
    "1. Score each finding by exploitability, impact, and "
    "exposure\n"
    "2. Identify attack chains spanning multiple findings\n"
    "3. Flag AI-specific risks as high priority (prompt "
    "injection, agent escape, tool abuse)\n"
    "4. Group related findings for efficient remediation\n"
    "5. Produce a risk narrative for CISO/engineering leads"
)
