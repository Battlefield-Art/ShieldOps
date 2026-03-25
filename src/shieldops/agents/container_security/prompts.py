"""Container Security Agent — LLM prompt templates."""

from pydantic import BaseModel, Field


class VulnerabilityAnalysisResult(BaseModel):
    """Structured output from LLM-assisted vulnerability triage."""

    summary: str = Field(description="Brief summary of vulnerability analysis")
    critical_count: int = Field(description="Number of critical findings")
    risk_level: str = Field(description="Overall risk level: low, medium, high, critical")
    priority_cves: list[str] = Field(description="CVEs that should be remediated first")
    recommended_actions: list[str] = Field(
        description="Recommended remediation actions in priority order"
    )


class RuntimeThreatAnalysisResult(BaseModel):
    """Structured output from LLM-assisted runtime threat analysis."""

    summary: str = Field(description="Brief summary of runtime threat analysis")
    threat_level: str = Field(description="Threat level: none, low, medium, high, critical")
    attack_chain: list[str] = Field(description="Steps in the identified attack chain, if any")
    immediate_actions: list[str] = Field(description="Actions to take immediately")
    kill_pod_recommended: bool = Field(
        description="Whether to kill the affected pod(s) immediately"
    )


class AdmissionPolicyResult(BaseModel):
    """Structured output from LLM-assisted admission policy evaluation."""

    summary: str = Field(description="Brief summary of admission evaluation")
    denied_count: int = Field(description="Number of images denied admission")
    policy_gaps: list[str] = Field(description="Gaps in current admission policies")
    hardening_recommendations: list[str] = Field(
        description="Recommendations for hardening admission controls"
    )


SYSTEM_VULNERABILITY_ANALYSIS = (
    "You are a container security specialist analyzing image vulnerabilities.\n"
    "Given the scan results:\n"
    "1. Triage CVEs by exploitability, CVSS score, and blast radius\n"
    "2. Identify images with the most critical exposure\n"
    "3. Determine if any CVEs are actively exploited in the wild\n"
    "4. Recommend a prioritized remediation order\n"
    "5. Flag supply-chain risks (e.g., base image vulnerabilities)"
)

SYSTEM_RUNTIME_THREAT_ANALYSIS = (
    "You are a Kubernetes runtime security analyst.\n"
    "Given detected runtime anomalies:\n"
    "1. Correlate anomalies to identify attack chains\n"
    "2. Determine if anomalies indicate active compromise vs. misconfiguration\n"
    "3. Map threats to MITRE ATT&CK container techniques\n"
    "4. Assess lateral movement risk and blast radius\n"
    "5. Recommend immediate containment actions"
)

SYSTEM_ADMISSION_POLICY = (
    "You are an admission control policy engineer for Kubernetes.\n"
    "Given the admission evaluation results:\n"
    "1. Identify gaps in current admission policies\n"
    "2. Recommend additional OPA/Gatekeeper constraints\n"
    "3. Balance security with developer velocity\n"
    "4. Suggest image provenance and signing requirements\n"
    "5. Recommend namespace-level policy differentiation"
)
