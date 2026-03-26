"""CNAPP Analyzer Agent — LLM prompt templates and output schemas."""

from pydantic import BaseModel, Field

# ------------------------------------------------------------------
# Structured output schemas
# ------------------------------------------------------------------


class PostureAnalysisOutput(BaseModel):
    """LLM output for CSPM posture analysis."""

    summary: str = Field(description="Executive summary of cloud posture")
    risk_level: str = Field(description="Overall risk: critical/high/medium/low")
    worst_controls: list[str] = Field(description="Top failing CIS controls")
    recommendations: list[str] = Field(description="Prioritized remediation actions")


class WorkloadAnalysisOutput(BaseModel):
    """LLM output for CWPP workload threat analysis."""

    summary: str = Field(description="Workload protection summary")
    critical_images: list[str] = Field(description="Container images with critical CVEs")
    runtime_threats: list[str] = Field(description="Active runtime threats detected")
    patch_priority: list[str] = Field(description="Prioritized patching order")


class EntitlementAnalysisOutput(BaseModel):
    """LLM output for CIEM entitlement analysis."""

    summary: str = Field(description="Identity entitlement risk summary")
    over_privileged_count: int = Field(description="Number of over-privileged identities")
    high_risk_identities: list[str] = Field(description="Identities with highest risk")
    right_sizing_actions: list[str] = Field(description="Permission right-sizing recommendations")


class CodeSecurityOutput(BaseModel):
    """LLM output for code/IaC security analysis."""

    summary: str = Field(description="Code security scan summary")
    critical_vulns: list[str] = Field(description="Critical IaC misconfigurations")
    fix_priority: list[str] = Field(description="Prioritized fix order")
    compliance_gaps: list[str] = Field(description="Compliance gaps from IaC issues")


class UnifiedRiskOutput(BaseModel):
    """LLM output for unified CNAPP risk correlation."""

    summary: str = Field(description="Unified risk assessment summary")
    overall_risk: str = Field(description="Overall risk: critical/high/medium/low")
    attack_paths: list[str] = Field(description="Cross-domain attack paths identified")
    top_actions: list[str] = Field(description="Top risk reduction actions")
    score_justification: str = Field(description="Justification for overall score")


# ------------------------------------------------------------------
# System prompts
# ------------------------------------------------------------------

SYSTEM_POSTURE_SCAN = (
    "You are a CSPM analyst scanning cloud posture "
    "across AWS, GCP, Azure, and Kubernetes.\n"
    "For the provided CIS benchmark results:\n"
    "1. Identify the worst-performing controls\n"
    "2. Calculate compliance rates per provider\n"
    "3. Flag critical misconfigurations with "
    "public exposure or missing encryption\n"
    "4. Provide prioritized remediation actions"
)

SYSTEM_WORKLOAD_ANALYSIS = (
    "You are a CWPP analyst assessing container "
    "and workload security.\n"
    "For the provided workload scan results:\n"
    "1. Identify container images with critical CVEs\n"
    "2. Detect runtime threats (crypto mining, "
    "reverse shells, privilege escalation)\n"
    "3. Prioritize patches by CVSS and "
    "exploitability\n"
    "4. Recommend image hardening actions"
)

SYSTEM_ENTITLEMENT_ANALYSIS = (
    "You are a CIEM analyst evaluating cloud "
    "identity entitlements.\n"
    "For the provided identity analysis:\n"
    "1. Identify over-privileged identities with "
    "high unused permission ratios\n"
    "2. Detect cross-account trust risks\n"
    "3. Recommend permission right-sizing policies\n"
    "4. Flag service accounts with admin-level "
    "access that violate least privilege"
)

SYSTEM_CODE_SECURITY = (
    "You are an IaC and code security analyst.\n"
    "For the provided scan results:\n"
    "1. Classify IaC misconfigurations by severity "
    "and blast radius\n"
    "2. Map issues to CWE IDs and compliance "
    "frameworks\n"
    "3. Suggest inline fixes for Terraform, "
    "CloudFormation, and K8s YAML\n"
    "4. Prioritize by risk-to-effort ratio"
)

SYSTEM_RISK_CORRELATION = (
    "You are a CNAPP risk correlation analyst.\n"
    "Correlate findings across CSPM, CWPP, CIEM, "
    "and code security domains:\n"
    "1. Identify cross-domain attack paths "
    "(e.g., over-privileged identity + public "
    "workload + IaC misconfig)\n"
    "2. Calculate a unified risk score 0-100\n"
    "3. Rank the top 5 risk-reduction actions\n"
    "4. Map to compliance framework coverage "
    "(CIS, NIST, SOC2, PCI-DSS, HIPAA, ISO27001)"
)
