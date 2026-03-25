"""Supply Chain Security Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class VulnerabilityAnalysisResult(BaseModel):
    """Structured output from LLM-assisted vulnerability analysis."""

    summary: str = Field(description="Brief summary of vulnerability findings")
    critical_count: int = Field(description="Number of critical vulnerabilities")
    exploitable_count: int = Field(description="Number of actively exploitable vulns")
    risk_level: str = Field(description="Overall risk level: low, medium, high, critical")
    priority_fixes: list[str] = Field(
        description="Top-priority packages to patch, ordered by severity"
    )
    recommended_actions: list[str] = Field(description="Recommended remediation actions")


class PipelineSecurityResult(BaseModel):
    """Structured output from LLM-assisted CI/CD security analysis."""

    summary: str = Field(description="Brief summary of pipeline security posture")
    threat_count: int = Field(description="Number of identified threats")
    most_severe_threat: str = Field(description="Description of the highest-severity threat")
    attack_scenarios: list[str] = Field(description="Plausible attack scenarios from the findings")
    hardening_steps: list[str] = Field(description="Ordered steps to harden pipelines")


class SupplyChainRiskResult(BaseModel):
    """Structured output from LLM-assisted overall risk assessment."""

    summary: str = Field(description="Brief overall supply chain risk summary")
    risk_score: float = Field(description="Composite risk score 0.0-1.0")
    risk_level: str = Field(description="Overall risk level: low, medium, high, critical")
    top_risks: list[str] = Field(description="Top supply chain risks identified")
    mitigation_plan: list[str] = Field(description="Prioritized mitigation steps")
    compliance_gaps: list[str] = Field(description="Compliance gaps found (SLSA, SSDF, etc.)")


SYSTEM_VULNERABILITY_ANALYSIS = (
    "You are a supply chain security analyst specializing in dependency vulnerabilities.\n"
    "Analyze the following SBOM and vulnerability scan results:\n"
    "1. Identify the most critical vulnerabilities by CVSS score and exploitability\n"
    "2. Assess transitive dependency risk — indirect deps are harder to patch\n"
    "3. Check for known exploit chains across multiple vulnerable packages\n"
    "4. Prioritize fixes: exploitable criticals first, then high-CVSS with fix available\n"
    "5. Flag typosquatting or dependency confusion indicators"
)

SYSTEM_PIPELINE_SECURITY = (
    "You are a DevSecOps engineer specializing in CI/CD pipeline security.\n"
    "Analyze the following pipeline configurations and findings:\n"
    "1. Identify supply chain attack vectors: compromised actions, script injection, secret leaks\n"
    "2. Check for mutable references (branch tags instead of SHA pinning)\n"
    "3. Verify artifact signing and provenance (SLSA compliance)\n"
    "4. Assess blast radius if a pipeline stage is compromised\n"
    "5. Recommend hardening: least-privilege runners, OIDC auth, ephemeral credentials"
)

SYSTEM_RISK_ASSESSMENT = (
    "You are a supply chain risk analyst assessing overall software supply chain posture.\n"
    "Given the SBOM, vulnerability scan, pipeline audit, and signature verification results:\n"
    "1. Compute a composite risk score weighing vulns, pipeline threats, unsigned artifacts\n"
    "2. Identify the most critical risk across all dimensions\n"
    "3. Map findings to supply chain frameworks: SLSA levels, NIST SSDF, OpenSSF Scorecard\n"
    "4. Produce a prioritized mitigation plan\n"
    "5. Flag any indicators of active supply chain compromise"
)
